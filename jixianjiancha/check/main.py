#!/usr/bin/env python
#encoding=utf-8

# __author__ test
# __time__ 2018-4-25

import sys
import paramiko
import time
import json
import commands
import ast
import threading

reload(sys)
sys.setdefaultencoding('utf-8')
lock=threading.Lock()

		
#登录远程服务器并执行命令		
def remote_ssh(ip,user,password):	
	try:
		#将脚本传送到远程服务器
		transport = paramiko.Transport((ip,22))
		transport.connect(username=user, password=password)
		
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(ip, 22, username=user, password=password, timeout=200)
		print u"[*]连接到远程服务器"
		#登录远程服务器的路径
		stdin, stdout, stderr=ssh.exec_command("pwd")
		path=stdout.read().strip("\n")

		sftp = paramiko.SFTPClient.from_transport(transport)
		sftp.put('jixianjiancha.tar.gz', '%s/jixianjiancha.tar.gz'%path)
		print u"[*]将脚本传送到远程服务器"
		time.sleep(20)
		
		
		stdin, stdout, stderr=ssh.exec_command('tar -xvf %s/jixianjiancha.tar.gz'%path)
		print u"[*]在远程服务器上解压脚本"
		time.sleep(10)
		stdin, stdout, stderr=ssh.exec_command("python %s/jixianjiancha/main.py"%path)
		print u"[*]在远程服务器上执行脚本......"
		#判断服务器上的脚本是否执行完成
		'''
		tag=True
		while(tag):
			stdin, stdout, stderr=ssh.exec_command("cat /root/jixianjiancha/tip.txt")
			if 'finsh' in stdout.read():
				tag=False
		'''
		time.sleep(30)
		#将远程服务器上的运行结果result.json获取到本地
		sftp.get('%s/jixianjiancha/result.json'%path,'result.json')
		print u"[*]将扫描结果拉取到本地,结果保存在result.json"
		time.sleep(10)
		sftp.close()
		transport.close()
		#删除远程服务器上的文件：
		stdin, stdout, stderr=ssh.exec_command("rm -rf %s/jixianjiancha*"%path)
		ssh.close()
		print u"[*]删除远程服务器上的文件"
		print u"[+]系统漏洞扫描结束"
		
	except Exception as e:
		print u"[-]连接失败,请重新连接"
		print e
	finally:
		ssh.close()
		transport.close()


#端口扫描，获取远程服务器端口信息，并写入json

def portScan(ip,user,password):
	try:
		result={}
		with open("result.json","r") as fn:
			data=fn.readlines()
			fn.close()
			result=json.loads(data[0])
		result[u"ip"]=ip
		result[u"username"]=user
		result[u"password"]=password
		#进行端口扫描
		print u"[*]对主机%s进行端口扫描......"%ip
		commandResult=commands.getoutput("python port_scan.py %s"%ip)
		result[u"端口详情"]=ast.literal_eval(commandResult)
		#将主机信息，端口扫描信息保存到json中
		with open("result.json",'w') as fn:
			json.dump(result,fn,ensure_ascii=False)
			fn.close()
		print u"[+]本次端口扫描结束"
	except Exception as e:
		print u"[-]端口扫描失败，请重新扫描"
		print e
	

'''
if __name__ == '__main__':
	ip="192.168.159.132"
	user="root"
	password="123.a"
	lock.acquire()
	remote_ssh(ip,user,password)
	lock.release()
	portScan(ip,user,password)
	print u"[-]本次扫描结束,结果保存在result.json文件中"
'''
ip=sys.argv[1]
username=sys.argv[2]
password=sys.argv[3]
lock.acquire()
remote_ssh(ip,user,password)
lock.release()
portScan(ip,user,password)
print u"[-]本次扫描结束,结果保存在result.json文件中"
commands.getoutput("echo 'finsh'>end.txt")
	
