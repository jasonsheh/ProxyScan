#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

from database import Database

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
        self.urls = []
        self.denies = [b"google.com", b"gvt2.com", b'mozilla.net', b'mozilla.com', b'baidu.com']

        # 创建socket对象
        self.https_sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect_client(self):
        try:
            self.proxy_sock.bind((self.host, self.port))
        except:
            sys.exit("python proxy bind error ")
        print("python proxy open")
        self.proxy_sock.listen(10)

    def run(self):
        self.connect_client()
        while True:
            try:
                conn, addr = self.proxy_sock.accept()
                # os.fork()
                # print("client connect:{0}:{1}".format(addr[0], addr[1]))

                # 接收数据
                client_data = conn.recv(data_size)

                if not client_data:
                    continue
                # print(client_data)

                # 分析得到 header 信息
                header = client_data.split(b"\r\n")
                for _header in header:
                    if b'Host:' in _header:
                        host = _header.split(b":")[1].strip()
                url = header[0].split(b" ")[1].strip()

                flag = 0
                for deny in self.denies:
                    if deny in url:
                        flag = 1
                if flag:
                    continue

                print(url)

                # 统计访问记录
                # print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
                result = {'url' : url}
                result['scheme'], result['host'], result['path'], \
                    result['params'], result['query'], result['fragment'] = urlparse(url)
                if b':' in result['host']:
                    result['port'] = result['host'].rsplit(b':')[1]
                else:
                    result['port'] = b'80'

                self.urls.append(url)

                if client_data.find(b'Connection') >= 0:
                    client_data = client_data.replace(b'keep-alive', b'close')
                else:
                    client_data += b'Connection: close\r\n'

                # 建立连接
                if url.endswith(b":443"):
                    https_sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                    https_sock.connect((host, 443))
                    https_sock.settimeout(10)
                    https_sock.sendall(client_data)
                    https_buf = b""
                    while True:
                        https_data = https_sock.recv(data_size)
                        if https_data:
                            https_buf += https_data
                        else:
                            break
                    conn.sendall(https_buf)
                    result['status_code'] = https_buf.split(b"\r\n")[0].split(b' ')[1]
                    https_sock.close()

                elif b':' in url:
                    http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # http_sock.settimeout(10)
                    http_sock.connect((host, int(result['port'])))
                    http_sock.sendall(client_data)
                    http_buf = b""
                    while True:
                        http_data = http_sock.recv(data_size)
                        if http_data:
                            http_buf += http_data
                        else:
                            break
                    conn.sendall(http_buf)

                    result['status_code'] = http_buf.split(b"\r\n")[0].split(b' ')[1]
                    http_sock.close()

                conn.close()

                print(result)

                Database().insert(result)

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
