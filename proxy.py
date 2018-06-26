#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

from database import Database
from scan import Scan

import socket
import os
import sys
import ssl
import gzip
import zlib
import datetime
import threading
import re
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto

from typing import List, Dict
data_size = 8192


class Proxy:
    def __init__(self):
        # self.q = queue.Queue(0)
        self.host: str = '0.0.0.0'
        self.port: int = 8000
        self.denies: List[bytes] = [b"google.com", b"gvt2.com", b'mozilla.net', b'mozilla.com', b'mozilla.org', b'firefox.com',
                       b'cnzz.com', b'google-analytics.com', b'tianqi.com']
        self.static_ext: List[bytes] = [b'.js', b'.css', b'.jpg', b'.png', b'.gif', b'.ico', b'.swf', b'.jpeg', b'.pdf']
        self.result: Dict = {}
        self.ca_lock = threading.Lock()

        # 创建socket对象
        # self.https_sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.db = Database()

    def connect_client(self):
        try:
            self.proxy_sock.bind((self.host, self.port))
            self.proxy_sock.listen(20)
        except Exception as e:
            print(e)
            sys.exit("python proxy bind error ")
        print("python proxy open")
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
            if charset in [b'gb2312' or b'GBK']:
                response_body = response_body.decode(encoding='GBK').encode('utf-8')
        return response_body

    @staticmethod
    def close_connection(client_data):
        if client_data.find(b'Connection') >= 0:
            client_data = client_data.replace(b'keep-alive', b'close')
        else:
            client_data += b'Connection: close\r\n'
        return client_data

    def filter(self, url, mode):
        if not url:
            return True

        if mode == 'host':
            for deny in self.denies:
                if deny in url:
                    return False

        elif mode == 'ext':
            for ext in self.static_ext:
                if url.endswith(ext):
                    return False

        return True

    @staticmethod
    def create_ca2(host):
        cert_file = "./cert/cacert.pem"
        key_file = "./cert/cakey.pem"
        with open(cert_file, "r") as my_cert_file:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, my_cert_file.read())

        with open(key_file, "r") as my_key_file:
            ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, my_key_file.read())

        # create a key pair
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "CN"
        cert.get_subject().ST = "JiangSu"
        cert.get_subject().L = "NanJing"
        cert.get_subject().O = "ProxyScan"
        cert.get_subject().OU = "ProxyScan CA"
        cert.get_subject().CN = host
        cert.set_serial_number(x509.random_serial_number())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)

        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(ca_key, "sha256")

        open("./cert/website/"+host.strip('*')+".cert.pem", "wt").write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode())
        open("./cert/website/"+host.strip('*')+".key.pem", "wt").write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode())

    @staticmethod
    def create_fake_ca(host):
        with open("./cert/cakey.pem", "rb") as key_file:
            key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        issuer = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"JiangSu"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"NanJing"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ProxyScan"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"ProxyScan CA"),
                    x509.NameAttribute(NameOID.COMMON_NAME, u"JasonSheh"),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"qq3039344@gmail.com"),
               ])

        subject = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"JiangSu"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"NanJing"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, host),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"ProxyScan CA"),
                    x509.NameAttribute(NameOID.COMMON_NAME, host),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"qq3039344@gmail.com"),
               ])
        if host.startswith('*.'):
            cert = x509.CertificateBuilder().subject_name(
                   subject
                ).issuer_name(
                    issuer
                ).public_key(
                   key.public_key()
                ).serial_number(
                   x509.random_serial_number()
                ).not_valid_before(
                   datetime.datetime.utcnow() - datetime.timedelta(1, 0, 0)
                ).not_valid_after(
                     datetime.datetime.utcnow() + datetime.timedelta(days=3650)
                ).add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(host), ]),
                    critical=False,
                ).sign(
                    key, hashes.SHA256(), default_backend()
                )
        else:
            cert = x509.CertificateBuilder().subject_name(
                    subject
                ).issuer_name(
                    issuer
                ).public_key(
                    key.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    datetime.datetime.utcnow() - datetime.timedelta(1, 0, 0)
                ).not_valid_after(
                    datetime.datetime.utcnow() + datetime.timedelta(days=3650)
                ).add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(host), x509.DNSName('*.'+host)]),
                    critical=False,
                ).sign(
                    key, hashes.SHA256(), default_backend()
                )

        # Write our certificate out to disk.
        with open("./cert/website/"+host.strip('*')+".pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def receive_https_data_from_client(self, conn, host):
        conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        try:
            context.load_cert_chain(certfile='./cert/website/'+host.strip('*')+'.cert.pem',
                                    keyfile='./cert/website/'+host.strip('*')+'.key.pem')
        except FileNotFoundError:
            print('FileNotFoundError', host)
        try:
            conn_stream = context.wrap_socket(conn, server_side=True)
            client_data = conn_stream.recv(data_size)
            return client_data, conn_stream
        # except ConnectionAbortedError:
        #     print('无法连接至', self.result['url'].decode())
        except Exception as e:
            print(e, self.result['url'].decode())

    def send_https_data_to_server(self, host, port, client_data):
        https_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # context = ssl.SSLContext()
        # context.load_default_certs()
        try:
            https_sock = ssl.wrap_socket(https_sock)
            https_sock.connect((host, 443))
            https_sock.sendall(client_data)
        except Exception as e:
            print(e)

        return https_sock

    def receive_https_data_from_server(self, https_sock, conn):
        https_data = b''
        while True:
            try:
                server_data = https_sock.recv(data_size)
                if server_data:
                    https_data += server_data
                    conn.send(server_data)
                else:
                    break
            except Exception as e:
                print(e, self.result['url'].decode(), server_data.decode())
                break
        return https_data

    def send_http_data_to_server(self, host, port, client_data):
        http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        http_sock.settimeout(20)
        try:
            http_sock.connect((host, port))
        except socket.timeout:
            print('socket.timeout', host)
        http_sock.sendall(client_data)
        return http_sock
    
    def receive_http_data_from_server(self, http_sock, conn, url):
        http_data = b''
        while True:
            try:
                server_data = http_sock.recv(data_size)
                if server_data:
                    http_data += server_data
                    conn.send(server_data)
                else:
                    break
            except Exception as e:
                print(e, url)
                break
        return http_data

    def client_data_analysis(self, client_data):
        if b'\r\n\r\n' in client_data:
            request_header, request_body = client_data.split(b"\r\n\r\n", 1)

            headers = request_header.split(b'\r\n')

            url = headers[0].split(b" ")[1].strip()
            if not url.startswith(b'http'):
                if url.endswith(b'443'):
                    url = b'https://' + url[:-4]
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

    def https_client_data_analysis(self, client_data):
        if b'\r\n\r\n' in client_data:
            request_header, request_body = client_data.split(b"\r\n\r\n", 1)

            headers = request_header.split(b'\r\n')

            path = headers[0].split(b" ")[1].strip()
            host = headers[1].split(b" ")[1].strip()
            url = b'https://' + host + path

            self.result = {'url': url, 'request_header': request_header}
            self.result['scheme'], self.result['host'], self.result['path'], self.result['params'], self.result['query'],\
            self.result['fragment'] = urlparse(url)

            if b':' in self.result['host']:
                self.result['host'], self.result['port'] = self.result['host'].rsplit(b':')
            else:
                self.result['port'] = b'80'

            self.result['method'] = client_data.split(b' ')[0]
            self.result['request_body'] = request_body

    def server_data_analysis(self, server_data):
        if b'\r\n\r\n' in server_data:
            response_header, response_body = server_data.split(b"\r\n\r\n", 1)

            self.result['response_header'] = response_header
            self.result['response_body'] = response_body
            self.result['status_code'] = response_header.split(b"\r\n")[0].split(b' ')[1]
            # print(self.result['status_code'].decode())
            if b'charset=' in server_data:
                # pattern = re.compile('charset=(.*?)[">]*\\\\r\\\\n')
                pattern = re.compile('charset=([-a-zA-Z_0-9]+)\S.')
                try:
                    self.result['charset'] = re.findall(pattern, str(server_data))[0]
                except IndexError:
                    print('charset', self.result['charset'], server_data)
            else:
                self.result['charset'] = ''
        else:
            print('server_data ', server_data)

    def run(self):
        self.connect_client()
        while True:
            try:
                conn, addr = self.proxy_sock.accept()
                t = threading.Thread(target=self.proxy, args=(conn, ))
                t.start()
            except KeyboardInterrupt:
                self.proxy_sock.close()
                self.db.clean()
                print("python proxy close")
                break

    def proxy(self, conn):
        server_data = ''
        client_data = conn.recv(data_size)

        self.client_data_analysis(client_data)

        # 对不在黑名单中的域名进行处理
        if self.filter(self.result['host'], 'host'):
            client_data = self.close_connection(client_data)

            # https的connect方法
            if self.result['method'] == b'CONNECT':
                if self.result['host'].decode().count('.') > 1:
                    host = '*.'+self.result['host'].decode().split('.', 1)[1]
                    if not os.path.exists("./cert/website/" + host + ".pem") and self.ca_lock.acquire():
                        # self.create_fake_ca(host)
                        self.create_ca2(host)
                        self.ca_lock.release()
                else:
                    host = self.result['host'].decode()
                    if not os.path.exists("./cert/website/" + host + ".pem") and self.ca_lock.acquire():
                        # self.create_fake_ca(host)
                        self.create_ca2(host)
                        self.ca_lock.release()

                client_data, conn = self.receive_https_data_from_client(conn, host)
                if client_data:
                    client_data = self.close_connection(client_data)
                    https_sock = self.send_https_data_to_server(self.result['host'].decode(), int(self.result['port']), client_data)
                    server_data = self.receive_https_data_from_server(https_sock, conn)
                    https_sock.close()

                    if not server_data:
                        return
                    self.https_client_data_analysis(client_data)

            else:
                # 建立连接， 发送接收数据
                http_sock = self.send_http_data_to_server(self.result['host'].decode(), int(self.result['port']), client_data)
                # print(client_data)
                server_data = self.receive_http_data_from_server(http_sock, conn, self.result['url'].decode())
                # print(server_data)
                http_sock.close()

            conn.close()
            if self.result['method'] != b'CONNECT' and self.filter(self.result['path'], 'ext'):
                self.server_data_analysis(server_data)
                # self.result['vul'] = Scan(self.result).run()
                self.result['vul'] = ''
                self.db.proxy_insert(self.result)
        else:
            http_sock = self.send_http_data_to_server(self.result['host'].decode(), int(self.result['port']), client_data)
            server_data = self.receive_http_data_from_server(http_sock, conn, self.result['url'].decode())
            http_sock.close()
            conn.close()


if __name__ == '__main__':
    Proxy().run()
    # print(Proxy().filter(b'www.cnzz.com', 'host'))
