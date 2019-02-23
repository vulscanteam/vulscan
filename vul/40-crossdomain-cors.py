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
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class CORS_POC(POCBase):
    vulID = '40'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  # 默认为1
    vulDate = '2018-07-10'  # 漏洞公开的时间,不知道就写今天

    author = 'arr0w1'  # PoC作者的大名
    createDate = '2018-07-10'  # 编写 PoC 的日期
    updateDate = '2018-07-10'  # PoC 更新的时间,默认和编写时间一样
    references = ''  # 漏洞地址来源,0day不用写
    name = 'crossdomain-cors'  # PoC 名称
    appPowerLink = '#'  # 漏洞厂商主页地址
    appName = 'http'  # 漏洞应用名称
    appVersion = 'all versions'  # 漏洞影响版本
    vulType = 'HTTP Request Smuggling'  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        crossdomain.xml CORS 跨域
    '''  # 漏洞简要描述
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"低危"  # 严重,高危,中危,低危

    def _verify(self):
        # 定义返回结果
        # 调用指纹方法
        result = {}
        output = Output(self)
        message = ''

        from urlparse import urlparse
        # 获取漏洞IP
        targetURL = self.url + '/crossdomain.xml'#xxx.com/

        targetURL = targetURL.replace("//crossdomain.xml", "/crossdomain.xml")


        try:
            r = req.get(url=targetURL, timeout=1, allow_redirects=False)  # 禁止重定向
            if r.status_code == 200:
                if r.text.find("<allow-access-from domain=\"*\"") > 0:
                    print('发现CORS 因为crossdomain.xml中存在：<allow-access-from domain=\"*\" ')
                    message = '发现CORS 因为crossdomain.xml中存在：<allow-access-from domain=\"*\"'
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['url'] = targetURL
                    result['VerifyInfo']['Payload'] = message

        except Exception as e:
            print e,targetURL

        return self.save_output(result)



    # 漏洞攻击
    def _attack(self):
        result = {}
        # 攻击代码
        return self._verify()

    def save_output(self, result):
        # 判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output


register(CORS_POC)