# ProxyScan

一个简单的http被动漏洞扫描器。存储基于sqlite3，web页面由flask实现，暂时只支持get类型sql注入检测

## 使用方法

初次使用请先执行
`python3 database.py`
以创建数据库

之后只需执行
`python3 proxy.py`

查看web界面
`python3 web.py`
访问127.0.0.1:5000

## 未完待续