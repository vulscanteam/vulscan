#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2014-2015 pocsuite developers (http://seebug.org)
See the file 'docs/COPYING' for copying permission
"""
#https://github.com/Nan3r/poc-t-db/blob/f1628efedf8dce3c88a1a099d39b99b797a186c3/script/rsync-weakpass.py


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
#pg数据库
class rsyncPOC(POCBase):
    vulID = '30'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-05-15' #漏洞公开的时间,不知道就写今天
    author = 'arr0w1' #  PoC作者的大名
    createDate ='2018-05-15'# 编写 PoC 的日期
    updateDate = '2018-05-15'# PoC 更新的时间,默认和编写时间一样
    references = 'https://rsync.samba.org'# 漏洞地址来源,0day不用写
    name = 'rsync Unauthorized access'# PoC 名称
    appPowerLink = 'https://rsync.samba.org'# 漏洞厂商主页地址
    appName = 'rsync'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'Weak-Password'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        rsync 未授权访问漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #指纹方法
    def _fingerprint(self):
        pass
        
    def _verify(self):
        import socket

        #调用指纹方法
        result={}
        output = Output(self)
        message = ''

        try:
            s = socket.socket()
            socket.setdefaulttimeout(1)#两秒超时
            port = 873
            ip = self.url.split(':')[1].replace('/','')
            s.connect((ip, port))
            print('Rsync未授权访问')
            message = 'Rsync 873端口 未授权访问'
            result['VerifyInfo'] = {}
            result['VerifyInfo']['url'] = ip
            result['VerifyInfo']['Payload'] = message
        except Exception as e:
            print(e)
        s.close()
        print '[+]30 poc done'
        return self.save_output(result)

    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output


    #攻击模块
    def _attack(self):
        result = {}
        # 攻击代码
        return self._verify()



#注册类
register(rsyncPOC)
