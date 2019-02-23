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


class DirlistPOC(POCBase):
    vulID = '12'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-06-26' #漏洞公开的时间,不知道就写今天

    author = 'ly55521' #  PoC作者的大名
    createDate = '2017-06-26'# 编写 PoC 的日期
    updateDate = '2017-06-26'# PoC 更新的时间,默认和编写时间一样
    references = 'http://0535code.com/article/20170626_1829.shtml'# 漏洞地址来源,0day不用写
    name = 'Parent Directory info'# PoC 名称
    appPowerLink = '#'# 漏洞厂商主页地址
    appName = '#'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'info-disclosure'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        目录列表漏洞
    ''' # 漏洞简要描述
    samples = ["http://hypem.com/download/",]# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危" #严重,高危,中危,低危

    #验证漏洞 pocsuite -r 12-Directory-list-info.py -u hypem.com --verify
    def _verify(self):
        #定义返回结果
        result = {}
        #获取漏洞url
        vul_url = '%s' % self.url

        r = req.get(vul_url)
        r_content = r.content
        import re
        title =re.findall(r"<title>(.*)</title>",r_content)[0]
        #print title
        if "Index of" in title:
            #print u"发现漏洞"
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vul_url
            result['VerifyInfo']['Payload'] = vul_url + str(r_content)             
        #print r_content
        #from bs4 import BeautifulSoup
        #soup = BeautifulSoup(r_content,'html.parser')
        #print soup.h1.string
        print '[+]12 poc done'
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

register(DirlistPOC)

