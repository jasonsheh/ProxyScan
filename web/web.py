#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

from database import Database

from flask import Flask, render_template
app = Flask(__name__)

max_page = Database().count()


@app.route('/')
@app.route('/index')
@app.route('/<int:page>')
def index(page=1):
    results = Database().select(page)
    return render_template('index.html',
                           results=results, page=page, max_page=max_page)

if __name__ == '__main__':
    app.run()
