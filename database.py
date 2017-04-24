#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

import sqlite3

conn = sqlite3.connect('proxyscan.db')
cursor = conn.cursor()

print("Opened database successfully")

cursor.execute('create table user('
               'id int primary key, '
               'url varchar(150), '
               'scheme varchar(10), '
               'path varchar(50), '
               'port varchar(5), '
               'status_code varchar(3)'
               ')')

cursor.close()
conn.close()
