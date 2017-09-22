
#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

from database import Database
from sqli import Sql

import socket
import os
import select
import sys
import ssl
import queue
import gzip
import zlib
import random
import datetime
import threading
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
data_size = 4096


class Proxy:
    def __init__(self):
        # self.q = queue.Queue(0)
        self.host = '0.0.0.0'
        self.port = 8080
        self.denies = [b"google.com", b"gvt2.com", b'mozilla.net', b'mozilla.com', b'mozilla.org', b'firefox.com']
        self.static_ext = [b'.js', b'.css', b'.jpg', b'.png', b'.gif', b'.ico']
        self.result = {}
        #self.epoll = select.epoll()
        #self.epoll.register(serversocket.fileno(), select.EPOLLIN)


        # 创建socket对象
        # self.https_sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect_client(self):
        try:
            self.proxy_sock.bind((self.host, self.port))
        except Exception as e:
            print('Error %s' % e)
            sys.exit("python proxy bind error ")
        print("python proxy open")
        self.proxy_sock.listen(20)
        # self.proxy_sock.setblocking(0)

    @staticmethod
    def gzip(data):
        buf = StringIO(data)
        f = gzip.GzipFile(fileobj=buf)
        return f.read()

    @staticmethod
    def deflate(data):
        try:
            return zlib.decompress(data, -zlib.MAX_WBITS)
        except zlib.error:
            return zlib.decompress(data)

    # 独立出解码函数以便复杂编码的处理
    @staticmethod
    def response_decode(response_header, response_body):
        if b'charset=' in response_header:
            charset = response_header.split(b'charset=')[1].split(b'\r\n')[0]
            if charset == (b'gb2312' or b'GBK'):
                response_body = response_body.decode(encoding='GBK').encode('utf-8')
        return response_body

    def fliter(self, url, mode):
        if mode == 'host' and url:
            for deny in self.denies:
                if deny in url:
                    return True

        elif mode == 'ext' and url:
            for ext in self.static_ext:
                if url.endswith(ext):
                    return True
        return False

    def create_fake_ca(self, host):
        with open("./cert/cakey.pem", "rb") as key_file:
            key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        issuer = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Jiangsu"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Nanjing"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ProxyScan"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"ProxyScan"),
                    x509.NameAttribute(NameOID.COMMON_NAME, u"JasonSheh"),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"3039344@qq.com"),
               ])

        subject = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Jiangsu"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Nanjing"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, host),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"ProxyScan"),
                    x509.NameAttribute(NameOID.COMMON_NAME, host),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"3039344@qq.com"),
               ])

        cert = x509.CertificateBuilder().subject_name(
               subject
            ).issuer_name(
               issuer
            ).public_key(
               key.public_key()
            ).serial_number(
               x509.random_serial_number()
            ).not_valid_before(
               datetime.datetime.utcnow()
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(host),]),
                critical=False,
            ).not_valid_after(
                 datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).sign(
                key, hashes.SHA256(), default_backend())

        # Write our certificate out to disk.
        with open("./cert/website/"+host+".pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def receive_https_data_from_client(self, conn, host):
        conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.load_cert_chain(certfile='./cert/website/'+host+'.pem', keyfile='./cert/cakey.pem')
        connstream = context.wrap_socket(conn, server_side=True)
        client_data = connstream.recv(data_size)

        return client_data, connstream

    def send_https_data_to_server(self, host, port, client_data):
        https_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        # context.load_default_certs()

        https_sock = context.wrap_socket(https_sock)
        https_sock.connect((host, port))

        https_sock.sendall(client_data)

        return https_sock

    def receive_https_data_from_server(self, https_sock, conn):
        https_data = b''
        try:
            while True:
                server_data = https_sock.recv(data_size)
                if server_data:
                    https_data += server_data
                    conn.send(server_data)
                else:
                    break
        except Exception as e:
            print(e, https_data)
        return https_data

    # http
    def send_http_data_to_server(self, host, port, client_data):
        http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        http_sock.settimeout(20)
        http_sock.connect((host, port))
        http_sock.sendall(client_data)
        return http_sock
    
    def receive_http_data_from_server(self, http_sock, conn):
        http_data = b''
        while True:
            server_data = http_sock.recv(data_size)
            if server_data:
                http_data += server_data
                conn.send(server_data)
            else:
                break
        return http_data

    def client_data_analysis(self, client_data):
        if b'\r\n\r\n' in client_data:
            request_header, request_body = client_data.split(b"\r\n\r\n", 1)

            headers = request_header.split(b'\r\n')

            url = headers[0].split(b" ")[1].strip()
            if not url.startswith(b'http'):
                if b':443' in url:
                    url = b'https://' + url
                else:
                    url = b'http://' + url

            self.result = {'url': url, 'request_header': request_header}
            self.result['scheme'], self.result['host'], self.result['path'], \
            self.result['params'], self.result['query'], self.result['fragment'] = urlparse(url)

            if b':' in self.result['host']:
                self.result['host'], self.result['port'] = self.result['host'].rsplit(b':')
            else:
                self.result['port'] = b'80'

            self.result['method'] = client_data.split(b' ')[0]
            self.result['request_body'] = request_body

    def server_data_analysis(self, server_data):
        response_header, response_body = server_data.split(b"\r\n\r\n", 1)

        self.result['response_header'] = response_header
        self.result['response_body'] = response_body
        self.result['status_code'] = response_header.split(b"\r\n")[0].split(b' ')[1]

    def run(self):
        self.connect_client()
        while True:
            try:
                conn, addr = self.proxy_sock.accept()
                t = threading.Thread(target=self.proxy, args=(conn, ))
                t.start()
            except KeyboardInterrupt:
                self.proxy_sock.close()
                print("python proxy close")
                break

    def proxy(self, conn):
            client_data = conn.recv(data_size)

            # 必要处理
            if not client_data:
                pass

            # 短连接
            if client_data.find(b'Connection') >= 0:
                client_data = client_data.replace(b'keep-alive', b'close')
            else:
                client_data += b'Connection: close\r\n'
            # 拆分数据
            # print(client_data)
            self.client_data_analysis(client_data)

            if self.fliter(self.result['host'], 'host'):
                pass

            # 统计访问记录
            # print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))

            # 数据整理

            if self.result['method'] == b'CONNECT':
                if not os.path.exists("./cert/website/"+self.result['host'].decode()+".pem"):
                    self.create_fake_ca(self.result['host'].decode())

                client_data, conn = self.receive_https_data_from_client(conn, self.result['host'].decode())

                if client_data.find(b'Connection') >= 0:
                    client_data = client_data.replace(b'keep-alive', b'close')
                else:
                    client_data += b'Connection: close\r\n'

                https_sock = self.send_https_data_to_server(self.result['host'].decode(), int(self.result['port']), client_data)
                server_data = self.receive_https_data_from_server(https_sock, conn)
                https_sock.close()
            else:

                # 建立连接， 发送接收数据
                http_sock = self.send_http_data_to_server(self.result['host'].decode(), int(self.result['port']), client_data)
                server_data = self.receive_http_data_from_server(http_sock, conn)
                http_sock.close()
            conn.close()

            if self.fliter(self.result['path'], 'ext'):
                pass
            # 对返回数据进行处理
            if not server_data:
                pass

            self.server_data_analysis(server_data)

            conn.close()

            # 安全测试处理内容 之后交由celery入队列处理

            # self.result['sqli'] = Sql(url.decode(), self.result['method'], self.result['request_body']).run()

            # print(self.result)
            # Database().insert(self.result)


if __name__ == '__main__':
    Proxy().run()
