#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

from database import Database

from script.sqli import Sql


class Scan:
    def __init__(self, result):
        self.result = result

    def run(self):
        return self.sql_scan()

    def sql_scan(self):
        if not Database().url_aleardy_test(self.result):
            flag, sql_info = Sql(self.result['url'], self.result['method'], self.result['request_body']).run()
            if flag:
                Database().scan_insert(sql_info)
                return 'sql'
        return ''
