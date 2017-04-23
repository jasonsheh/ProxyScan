#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

import socket
import sys
import ssl
import time

data_size = 2048


class Proxy:
    def __init__(self):
        self.host = '0.0.0.0'
        self.port = 8000

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

                # 统计访问记录
                print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
                print(b'host: '+host)
                print(b'url: '+url)

                if b"google.com" in url:
                    continue
                if b"gvt2.com" in url:
                    continue

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

                    https_sock.close()

                else:
                    http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # http_sock.settimeout(10)
                    http_sock.connect((host, 80))
                    http_sock.sendall(client_data)
                    http_buf = b""
                    while True:
                        http_data = http_sock.recv(data_size)

                        if http_data:
                            http_buf += http_data
                        else:
                            break
                    conn.sendall(http_buf)

                    http_sock.close()

                conn.close()
                print('finish!')

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
