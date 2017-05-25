#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

from database import Database
from sqli import Sql

import os
import socket
import sys
import ssl
import time
import queue
from urllib.parse import urlparse

data_size = 2048


class Proxy:
    def __init__(self):
        self.q = queue.Queue(0)
        self.host = '0.0.0.0'
        self.port = 8000
        self.denies = [b"google.com", b"gvt2.com", b'mozilla.net', b'mozilla.com', b'firefox.com']
        self.static_ext = [b'.js', b'.css', b'.jpg', b'.png', b'.gif', b'.ico']

        # 创建socket对象
        self.https_sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect_client(self):
        try:
            self.proxy_sock.bind((self.host, self.port))
        except Exception as e:
            print('Error %s' % (e))
            sys.exit("python proxy bind error ")
        print("python proxy open")
        self.proxy_sock.listen(10)

    def fliter(self, url, mode):
        flag = 0
        if mode == 'host':
            for deny in self.denies:
                if deny in url:
                    flag = 1
                    break

        elif mode == 'ext':
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
                # print("client connect:{0}:{1}".format(addr[0], addr[1]))

                # 发送的总数据
                client_data = conn.recv(data_size)

                if not client_data:
                    continue

                # 分析得到 header 信息
                request_header = client_data.split(b"\r\n\r\n")[0]
                request_data = client_data.split(b"\r\n\r\n")[1]

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

                result = {'url': url, 'request_header': request_header}
                result['scheme'], result['host'], result['path'], \
                    result['params'], result['query'], result['fragment'] = urlparse(url)

                if b':' in result['host']:
                    result['port'] = result['host'].rsplit(b':')[1]
                else:
                    result['port'] = b'80'

                result['method'] = client_data.split(b' ')[0]
                result['request_data'] = request_data

                if client_data.find(b'Connection') >= 0:
                    client_data = client_data.replace(b'keep-alive', b'close')
                else:
                    client_data += b'Connection: close\r\n'

                # 建立连接
                if result['port'] == b'443':
                    https_sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                    https_sock.connect((host, 443))
                    https_sock.settimeout(10)
                    https_sock.sendall(client_data)
                    host_data = b''
                    while True:
                        https_data = https_sock.recv(data_size)
                        if https_data:
                            host_data += https_data
                            conn.sendall(https_data)
                        else:
                            break

                    if not host_data:
                        conn.close()
                        continue
                    https_sock.close()

                else:
                    http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    http_sock.settimeout(10)
                    http_sock.connect((host, int(result['port'])))
                    http_sock.sendall(client_data)
                    host_data = b''
                    while True:
                        http_data = http_sock.recv(data_size)
                        if http_data:
                            host_data += http_data
                            conn.sendall(http_data)
                        else:
                            break

                    if not host_data:
                        conn.close()
                        continue
                    http_sock.close()

                conn.close()

                response_header = client_data.split(b"\r\n\r\n")[0]
                response_data = client_data.split(b"\r\n\r\n")[1]

                result['response_header'] = response_header
                result['response_data'] = response_data
                result['status_code'] = response_header.split(b"\r\n")[0].split(b' ')[1]

                conn.close()

                if self.fliter(result['path'], 'ext'):
                    continue

                s = Sql(url.decode(), result['method'], result['request_data'])
                result['sqli'] = s.run()

                print(result)
                Database().insert(result)

            except BrokenPipeError:
                conn.close()
                continue
            except TimeoutError:
                conn.close()
                continue
            except KeyboardInterrupt:
                break

        # 关闭所有连接
        self.proxy_sock.close()
        print("python proxy close")


def main():
    s = Proxy()
    s.run()

if __name__ == '__main__':
    main()
