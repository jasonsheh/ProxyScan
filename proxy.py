#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

import socket
import sys
import ssl
import time


host = '0.0.0.0'
port = 8000

# 创建socket对象


def connect_client():
    try:
        proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_sock.bind((self.host, self.port))
    except:
        sys.exit("python proxy bind error ")
    print("python proxy open")
    proxy_sock.listen(10)
    conn, addr = proxy_sock.accept()
    print("client connect:{0}:{1}".format(addr[0], addr[1]))
    self.handle_connection(conn)


def handle_connection(conn):
    header = get_header(conn)


def get_header(conn):
    client_data = conn.recv(1024)

    if not client_data:
        return
    print(client_data)

    # 分析得到 header 信息
    header = client_data.split(b"\r\n")
    host = header[1].split(b":")[1].strip()
    url = header[0].split(b" ")[1].strip()

    # 统计访问记录
    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
    print(host)
    print(url)

    return header, ur

def run():
    while True:
        try:
            if b"google.com" in url:
                continue

            # 建立连接
            if url.endswith(b":443"):
                https_sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                https_sock.connect((host, 443))
                https_sock.settimeout(20)
                https_sock.sendall(client_data)
                while True:
                    https_data = https_sock.recv(1024)
                    if https_data:
                        conn.send(https_data)
                        print(1)
                    else:
                        break

                https_sock.close()

            else:
                http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                http_sock.settimeout(20)
                http_sock.connect((host, 80))
                http_sock.sendall(client_data)
                while True:
                    http_data = http_sock.recv(1024)
                    if http_data:
                        conn.send(http_data)
                        print(1)
                    else:
                        break

                http_sock.close()

            print('finish!')

        except KeyboardInterrupt:
            break

    # 关闭所有连接
    self.proxy_sock.close()
    print("python proxy close")



