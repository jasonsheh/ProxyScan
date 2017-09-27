#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

from script.sqli import Sql


class Scan:
    def __init__(self, result):
        self.result = result

    def run(self):

        Sql(self.result['url'], self.result['method'], self.result['request_body']).run()


