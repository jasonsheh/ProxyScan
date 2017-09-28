#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

import sqlite3


class Database:
    def __init__(self):
        self.conn = sqlite3.connect('/home/jasonsheh/Tools/python/ProxyScan/proxyscan.db')
        self.cursor = self.conn.cursor()

    def create_database(self):
        self.create_proxy_result()
        self.create_scan_result()

    def create_proxy_result(self):
        self.cursor.execute('create table proxy('
                            'id integer primary key, '
                            'url varchar(255), '
                            'scheme varchar(10), '
                            'host varchar(255), '
                            'path varchar(64), '
                            'port varchar(6), '
                            'query varchar(255), '
                            'status_code varchar(3), '
                            'charset varchar(10), '
                            'method varchar(10), '
                            'sqli tinyint, '
                            'request_header text, ' 
                            'request_body text, ' 
                            'response_header text, ' 
                            'response_body text ' 
                            ')')

        print("create proxy successfully")

    def proxy_insert(self, result):
        url = result['url'].decode()
        scheme = result['scheme'].decode()
        host = result['host'].decode()
        path = result['path'].decode()
        port = result['port'].decode()
        query = result['query'].decode()
        status_code = result['status_code'].decode()
        charset = result['charset']
        method = result['method'].decode()
        sqli = result['sqli']
        request_header = result['request_header'].decode()
        if result['request_body']:
            request_body = result['request_body'].decode()
        else:
            request_body = str(result['request_body'])[2:-1]

        response_header = result['response_header'].decode()
        if result['request_body'] and charset:
            response_body = result['response_body'].decode(charset)
        else:
            response_body = str(result['response_body'])[2:-1]

        sql = "insert into proxy (url, scheme, host, path, port, query, status_code, charset, method, " \
              "sqli, request_header, request_body, response_header, response_body) " \
              "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        self.cursor.execute(sql, (url, scheme, host, path, port, query, status_code, charset, method,
                                  sqli, request_header, request_body, response_header, response_body))
        self.conn.commit()

        self.clean()

    def select_by_page(self, page):
        sql = 'select * from proxy order by id desc limit ?, 15'
        self.cursor.execute(sql, ((page-1)*15, ))
        results = self.cursor.fetchall()

        _results = []
        for result in results:
            _result = {}
            _result['id'] = result[0]
            _result['url'] = result[1]
            _result['scheme'] = result[2]
            _result['host'] = result[3]
            _result['path'] = result[4]
            _result['port'] = result[5]
            _result['query'] = result[6]
            _result['status_code'] = result[7]
            _result['charset'] = result[8]
            _result['method'] = result[9]
            _result['sqli'] = result[10]
            _result['request_header'] = result[11]
            _result['request_body'] = result[12]
            _result['response_header'] = result[13]
            _result['response_body'] = result[14]
            _results.append(_result)

        self.clean()

        return _results

    def select_detail(self, _id):
        sql = 'select * from proxy where id = ?'
        self.cursor.execute(sql, (_id, ))
        result = self.cursor.fetchone()
        _result = {}
        _result['id'] = result[0]
        _result['url'] = result[1]
        _result['scheme'] = result[2]
        _result['host'] = result[3]
        _result['path'] = result[4]
        _result['port'] = result[5]
        _result['query'] = result[6]
        _result['status_code'] = result[7]
        _result['charset'] = result[8]
        _result['method'] = result[9]
        _result['sqli'] = result[10]
        _result['request_header'] = result[11]
        _result['request_body'] = result[12]
        _result['response_header'] = result[13]
        _result['response_body'] = result[14]

        self.clean()

        return _result

    def select_search(self, page, host):
        sql = 'select * from proxy where host like ? order by id desc limit ?, 15'
        self.cursor.execute(sql, ('%'+host, (page-1)*15))
        results = self.cursor.fetchall()

        _results = []
        for result in results:
            _result = {}
            _result['id'] = result[0]
            _result['url'] = result[1]
            _result['scheme'] = result[2]
            _result['host'] = result[3]
            _result['path'] = result[4]
            _result['port'] = result[5]
            _result['query'] = result[6]
            _result['status_code'] = result[7]
            _result['charset'] = result[8]
            _result['method'] = result[9]
            _result['sqli'] = result[10]
            _result['request_header'] = result[11]
            _result['request_body'] = result[12]
            _result['response_header'] = result[13]
            _result['response_body'] = result[14]
            _results.append(_result)

        self.clean()

        return _results

    def count(self, mode):
        sql = 'select count(*) from ?'
        self.cursor.execute(sql, (mode,))
        max_page = self.cursor.fetchone()
        return (max_page[0] // 15) + 1

    def count_by_host(self, host):
        sql = 'select count(*) from proxy where host = ?'
        self.cursor.execute(sql, (host, ))
        max_page = self.cursor.fetchone()
        return (max_page[0] // 15) + 1

    def create_scan_result(self):
        self.cursor.execute('create table scan('
                            'id integer primary key, '
                            'url varchar(255), '
                            'vul varchar(16), '
                            ')')

        print("create scan successfully")

    def scan_insert(self, result):
        url = result['url'].decode()
        vul = result['vul'].decode()

        sql = "insert into scan (url, vul ) values (?, ?)"
        self.cursor.execute(sql, (url, vul))
        self.conn.commit()
        self.clean()

    def clean(self):
        self.cursor.close()
        self.conn.close()

if __name__ == '__main__':
    Database().create_proxy_result()
