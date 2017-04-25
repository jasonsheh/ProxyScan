#!/usr/bin/python
# __author__ = 'jasonsheh'
# -*- coding:utf-8 -*-

from database import Database

from flask import Flask, render_template
app = Flask(__name__)


@app.route('/')
@app.route('/index')
def index():
    results = Database().select()
    return render_template('index.html', results=results)

if __name__ == '__main__':
    app.run()
