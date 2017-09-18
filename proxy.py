
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
import random
import datetime
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
data_size = 2048


class Proxy:
    def __init__(self):
        self.q = queue.Queue(0)
        self.host = '0.0.0.0'
        self.port = 8080
        self.denies = [b"google.com", b"gvt2.com", b'mozilla.net', b'mozilla.com', b'mozilla.org', b'firefox.com']
        self.static_ext = [b'.js', b'.css', b'.jpg', b'.png', b'.gif', b'.ico']

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
        self.proxy_sock.listen(10)

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

    def read_key_from_local(self):
        with open("./cert/cert.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        return private_key

    def create_fake_ca(self, host):
        key = self.read_key_from_local()
        subject = issuer = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"TS"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"TS"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TS"),
                    x509.NameAttribute(NameOID.COMMON_NAME, host),
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
            ).not_valid_after(
                 # Our certificate will be valid for 10 days
               datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).sign(key, hashes.SHA256(), default_backend())
        # Write our certificate out to disk.
        with open("./cert/website/"+str(host)+".pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def receive_https_data_from_client(self, conn, host):
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        # context.load_cert_chain(certfile="key.crt", keyfile="key.pem")
        print(host)
        context.load_cert_chain(certfile='./cert/website/'+host+'.pem', keyfile='./cert/cert.key')
        connstream = context.wrap_socket(conn, server_side=True)
        client_data = b''
        while True:
            https_data = connstream.recv(4096)
            if https_data:
                client_data += https_data
            else:
                break

        print(client_data)
        return client_data

    def send_https_data_to_server(self, host, port, client_data):
        https_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        https_sock.settimeout(20)
        https_sock.connect((host, port))
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.load_cert_chain(certfile='CA.crt')
        https_sock = context.wrap_socket(https_sock, server_side=True)
        https_sock.sendall(client_data)

        return https_sock

    def receive_https_data_from_server(self, https_sock, conn):
        http_data = b''
        while True:
            server_data = https_sock.recv(data_size)
            if server_data:
                http_data += server_data
                conn.send(server_data)
            else:
                break
        return http_data

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
                print(client_data)
                request_header, request_body = client_data.split(b"\r\n\r\n", 1)
                # 分析得到 header 信息
                headers = request_header.split(b'\r\n')
                for header in headers:
                    if b'Host:' in header:
                        host = header.split(b":")[1].strip()

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
                    result['host'], result['port'] = result['host'].rsplit(b':')
                    result['port'] = result['host'].rsplit(b':')
                else:
                    result['port'] = b'80'

                result['method'] = client_data.split(b' ')[0]
                result['request_body'] = request_body

                if result['method'] == b'CONNECT':
                    conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
                    self.create_fake_ca(result['host'].decode())

                    client_data = self.receive_https_data_from_client(conn, result['host'].decode())
                    print(client_data)
                    https_sock = self.send_https_data_to_server(host, int(result['port']), client_data)
                    self.receive_https_data_from_server(https_sock, conn)
                    continue


                # 建立连接， 发送接收数据
                http_sock = self.send_http_data_to_server(host, int(result['port']), client_data)
                server_data = self.receive_http_data_from_server(http_sock, conn)
            
                http_sock.close()
                conn.close()

                # 对返回数据进行处理
                if not server_data:
                    continue

                response_header, response_body = server_data.split(b"\r\n\r\n", 1)
                # 好像没什么用
                # response_body = self.response_decode(response_header, response_body)

                if self.fliter(result['path'], 'ext'):
                    continue

                result['response_header'] = response_header
                result['response_body'] = response_body
                result['status_code'] = response_header.split(b"\r\n")[0].split(b' ')[1]

                conn.close()

                # 安全测试处理内容 之后交由celery入队列处理

                # result['sqli'] = Sql(url.decode(), result['method'], result['request_body']).run()

                # print(result)
                # Database().insert(result)

            except TimeoutError:
                conn.close()
                continue
            except KeyboardInterrupt:
                break

        # 关闭所有连接
        self.proxy_sock.close()
        print("python proxy close")


def gen_rand_serial(length):
    num = ''
    nlist = random.sample(['1', '2', '3', '4', '5', '6', '7', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f'], length)
    for n in nlist:
        num += str(n)
    return int(num.encode('hex'), 16)



if __name__ == '__main__':
    Proxy().run()
