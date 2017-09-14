#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

from database import Database
from sqli import Sql

import socket
import sys
import ssl
import queue
import gzip
import zlib
from urllib.parse import urlparse
data_size = 2048


class Proxy:
    def __init__(self):
        self.q = queue.Queue(0)
        self.host = '0.0.0.0'
        self.port = 8000
        self.denies = [b"google.com", b"gvt2.com", b'mozilla.net', b'mozilla.com', b'mozilla.org', b'firefox.com']
        self.static_ext = [b'.js', b'.css', b'.jpg', b'.png', b'.gif', b'.ico']

        # 创建socket对象
        self.https_sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect_client(self):
        try:
            self.proxy_sock.bind((self.host, self.port))
        except Exception as e:
            print('Error %s' % e)
            sys.exit("python proxy bind error ")
        print("python proxy open")
        self.proxy_sock.listen(10)

    @staticmethod
    def gzip(self, data):
        buf = StringIO(data)
        f = gzip.GzipFile(fileobj=buf)
        return f.read()

    @staticmethod
    def deflate(self, data):
        try:
            return zlib.decompress(data, -zlib.MAX_WBITS)
        except zlib.error:
            return zlib.decompress(data)

    def fliter(self, url, mode):
        flag = 0
        if mode == 'host' and url:
            for deny in self.denies:
                if deny in url:
                    flag = 1
                    break

        elif mode == 'ext' and url:
            for ext in self.static_ext:
                if url.endswith(ext):
                    flag = 1
                    break

        if flag:
            return True
        else:
            return False

    def run(self):
        self.connect_client()
        while True:
            try:
                conn, addr = self.proxy_sock.accept()

                # 发送的总数据
                client_data = conn.recv(data_size)

                # 必要处理
                if not client_data:
                    continue
                '''
                if b'Accept-Encoding: gzip, deflate' in client_data:
                    client_data = client_data.replace(b'gzip, deflate', b'')
                '''

                if client_data.find(b'Connection') >= 0:
                    client_data = client_data.replace(b'keep-alive', b'close')
                else:
                    client_data += b'Connection: close\r\n'

                # 拆分数据
                request_header = client_data.split(b"\r\n\r\n")[0]
                request_body = client_data.split(b"\r\n\r\n")[1]

                # 分析得到 header 信息
                headers = request_header.split(b'\r\n')
                for _header in headers:
                    if b'Host:' in _header:
                        host = _header.split(b":")[1].strip()

                url = headers[0].split(b" ")[1].strip()
                if not url.startswith(b'http'):
                    if b':443' in url:
                        url = b'https://'+url
                    else:
                        url = b'http://'+url

                if self.fliter(url, 'host'):
                    continue

                # 统计访问记录
                # print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))

                # 数据整理
                result = {'url': url, 'request_header': request_header}
                result['scheme'], result['host'], result['path'], \
                    result['params'], result['query'], result['fragment'] = urlparse(url)

                if b':' in result['host']:
                    result['port'] = result['host'].rsplit(b':')[1]
                else:
                    result['port'] = b'80'

                result['method'] = client_data.split(b' ')[0]
                result['request_body'] = request_body

                # 建立连接， 发送接收数据
                http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                http_sock.settimeout(20)
                http_sock.connect((host, int(result['port'])))
                http_sock.sendall(client_data)
                server_data = b''
                while True:
                    http_data = http_sock.recv(data_size)
                    if http_data:
                        server_data += http_data
                        conn.send(http_data)
                    else:
                        break
                http_sock.close()
                conn.close()

                if not server_data:
                    continue

                if b'Accept-Encoding: gzip, deflate' in server_data:
                    server_data = self.gizp(server_data)

                response_header, response_body = server_data.split(b"\r\n\r\n", 1)

                if b'charset=' in response_header:
                    charset = response_header.split(b'charset=')[1].split(b'\r\n')[0]
                    if charset == (b'gb2312' or b'GBK'):
                        response_body = response_body.decode(encoding='GBK').encode('utf-8')

                if b'Content-Type: image/jpeg\n' in response_header:
                    continue
                if b'Content-Type: application/javascript\r\n' in response_header:
                    continue

                result['response_header'] = response_header
                result['response_body'] = response_body
                result['status_code'] = response_header.split(b"\r\n")[0].split(b' ')[1]

                conn.close()

                if self.fliter(result['path'], 'ext'):
                    continue

                s = Sql(url.decode(), result['method'], result['request_body'])
                result['sqli'] = s.run()

                print(result)
                # Database().insert(result)

            except TimeoutError:
                conn.close()
                continue
            except KeyboardInterrupt:
                break

        # 关闭所有连接
        self.proxy_sock.close()
        print("python proxy close")


if __name__ == '__main__':
    Proxy().run()
