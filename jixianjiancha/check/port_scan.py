#!/usr/bin/env python
#encoding=utf-8

# __author__ test
# __time__ 2018-4-25

import nmap
import sys
import re


reload(sys)
sys.setdefaultencoding('utf-8')


class  portScanner(object):
	"""docstring for  portScanner"""
	def __init__(self, ip="127.0.0.1",port="-1"):
		self.ip = ip.strip().strip("\n")  #需要扫描的ip
		self.port = port #需要的端口,默认是常用端口

	def scan(self):
		ipPattern="^((25[0-5]|2[0-4]\\d|[1]{1}\\d{1}\\d{1}|[1-9]{1}\\d{1}|\\d{1})($|(?!\\.$)\\.)){4}$"
		ipFormat=re.match(ipPattern,self.ip)  # 判断ip格式是否正确
		if(ipFormat==None):
			return {u"端口扫描":{"":{"describe":u"ip 格式不正确，请重新输入","tag":1,"level":u"中危","repair":u"请重新输入ip"}},"rows":1}
			

		try:
			scan = nmap.PortScanner()
			if self.port=="-1":
				#scan.scan(hosts=self.ip,arguments="-p 0-65535  -sV -sC -host-timeout 180 --version-all")
				scan.scan(hosts=self.ip,arguments="-p 0-65535 -sT -sV")
			else:
				scan.scan(hosts=self.ip,arguments="-sS -sV -p %s"%(self.port))
		
			ports=scan[self.ip]['tcp'].keys()
			#print scan
			result={u"端口扫描":{}}
			{u"端口扫描":{"":{"describe":u"ip 格式不正确，请重新输入","tag":1}}}
			openPort=[{u"协议_ip":u"name_product_version"}] #开放的端口
			rows=0  #计数 开放端口的数量
			for p in ports:
				if(scan[self.ip]['tcp'][p]['state']=="open"):
					rows+=1
					result[u"端口扫描"][p]={}
					result[u"端口扫描"][p]['describe']=scan[self.ip]['tcp'][p]['product']+" :"+scan[self.ip]['tcp'][p]['version']
					if (p in [80,443]):
						result[u"端口扫描"][p]['tag']=0
					else:
						result[u"端口扫描"][p]['tag']=1
					result[u"端口扫描"][p]['level']=u"高危"
					result[u"端口扫描"][p]['repair']=u"在不影响业务前提下，关闭该端口"
			

			#判断开放端口数量是否为0
			if(rows==0):
				return {u"端口扫描":{"":{"describe":u"没有端口开放","tag":0,"level":u"中危","repair":u"暂无"}},"rows":1}
			result['rows']=rows

					#tmp={u"tcp_%s"%(p):u"%s_%s_%s"%(scan[self.ip]['tcp'][p]['name'],scan[self.ip]['tcp'][p]['product'],scan[self.ip]['tcp'][p]['version'])}
					#openPort.append(tmp)
			'''
			openPort=[[u"协议","ip","name","product","version"]] #开放的端口
			for p in ports:
				if(scan[self.ip]['tcp'][p]['state']=="open"):
					tmp=["tcp",p,scan[self.ip]['tcp'][p]['name'],scan[self.ip]['tcp'][p]['product'],scan[self.ip]['tcp'][p]['version']]
					openPort.append(tmp)
			'''
			return result
		except Exception as e:
			print e
			return {u"端口扫描":{"":{"describe":u"扫描失败,请手动重新扫描","tag":1,"level":u"中危","repair":u"请重新扫描服务器开放的端口"}},"rows":1}




a=portScanner(sys.argv[1])
print a.scan()
