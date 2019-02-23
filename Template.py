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
class RedisPOC(POCBase):
    vulID = '1'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2017-02-21' #漏洞公开的时间,不知道就写今天

    author = 'ly55521' #  PoC作者的大名
    createDate = '2017-02-21'# 编写 PoC 的日期
    updateDate = '2017-02-21'# PoC 更新的时间,默认和编写时间一样
    references = 'http://0535code.com/article/20161124_1251.shtml'# 漏洞地址来源,0day不用写
    name = 'redis Unauthorized access'# PoC 名称
    appPowerLink = 'https://www.redis.io/'# 漏洞厂商主页地址
    appName = 'redis'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'Weak-Password'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        redis未授权漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #指纹方法
    def _fingerprint(self):
        pass
        
    #验证模块 pocsuite -r 1-redis.py -u 10.1.5.26 --verify
    def _verify(self):
        #调用指纹方法
        pass

    #攻击模块
    def _attack(self):
        pass

    #输出报告
    def save_output(self, result):
        pass

#注册类
register(RedisPOC)


"""
PoC 编写规范及要求说明 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md

使用方法 https://github.com/knownsec/Pocsuite/blob/master/docs/translations/USAGE-zh.md

集成 Pocsuite https://github.com/knownsec/Pocsuite/blob/master/docs/INTEGRATE.md

钟馗之眼 批量验证
pocsuite -r 1-redis-getshell.py --verify --dork "redis"  --max-page 50 --search-type host --report report.html
pocsuite -r 1-redis-getshell.py --verify -f results.txt --threads 10 --report report.html
"""

"""##使用默认端口检测：

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
    _port = "6379"
"""


