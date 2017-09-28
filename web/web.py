#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

import sys

from database import Database

from flask import Flask, render_template, request, redirect
app = Flask(__name__)


@app.route('/')
@app.route('/index')
@app.route('/<int:page>')
def index(page=1):
    results = Database().select_by_page(page)
    max_page = Database().count('proxy')
    return render_template('index.html',
                           results=results, page=page, max_page=max_page)


@app.route('/detail/<int:_id>')
def detail(_id):
    result = Database().select_detail(_id)
    return render_template('detail.html',
                           result=result,
                           request_header=result['request_header'].split(r'\r\n'),
                           response_header=result['response_header'].split(r'\r\n'),)


@app.route('/<string:host>/<int:page>')
def search_host(host, page):
    results = Database().select_search(page, host)
    max_host_page = Database().count_by_host(host)
    return render_template('host.html',
                           results=results, page=page, max_page=max_host_page)


@app.route('/search', methods=['POST'])
def search():
    if request.method == 'POST':
        if request.form.get('host'):
            host = request.form.get('host')
            return redirect('/'+host+'/1')


if __name__ == '__main__':
    try:
        app.run()
    except KeyboardInterrupt:
        sys.exit()
