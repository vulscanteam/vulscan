#!/usr/bin/env python
#encoding=utf-8

# __author__ test
# __time__ 2018-4-25

import sys
import os
import paramiko
import time
import json
import commands
import ast
import threading
from scp import SCPClient

reload(sys)
sys.setdefaultencoding('utf-8')
lock=threading.Lock()

		
#将脚本传到服务器,并解压
def transRemote(ip,user,password):
	try:

		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(ip, 22, username=user, password=password, timeout=200)
		stdin, stdout, stderr=ssh.exec_command("pwd")
		path=stdout.read().strip("\n")

		#查看python版本
		stdin, stdout, stderr=ssh.exec_command("python -V")
		pythonVsersion=stdout.read().strip("\n")
		scriptName="jixianjiancha.tar.gz"
		if(len(pythonVsersion)==0):
			scriptName="jixianjiancha.tar.gz"
		else:
			if(pythonVsersion.split()[1].startswith("3")):
				scriptName="jixianjiancha2.tar.gz"

		current_path=os.getcwd()
		#print current_path
		scpclient = SCPClient(ssh.get_transport(), socket_timeout=15.0)
		scpclient.put('%s/jixianjiancha/check/%s'%(current_path,scriptName), '%s/jixianjiancha.tar.gz'%path)
		print u"[*]将脚本传送到远程服务器"

		index=0
		script_number=12
		while(index<10):
			stdin, stdout, stderr=ssh.exec_command('tar -xvf %s/jixianjiancha.tar.gz'%path)
			time.sleep(2)
			stdin, stdout, stderr=ssh.exec_command("ls %s"%(path))
			scripts=len(stdout.read().strip("\n"))
			if(scripts==12):
				index=11
			else:
				index+=1
		print u"[*]在远程服务器上解压脚本"
		ssh.close()
		return True
	except Exception as e:
		print e
	return False


#循环遍历脚本
def remote_ssh(ip,user,password,script):
	try:
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(ip, 22, username=user, password=password, timeout=200)
		stdin, stdout, stderr=ssh.exec_command("pwd")
		path=stdout.read().strip("\n")
		stdin, stdout, stderr=ssh.exec_command("python %s/jixianjiancha/%s"%(path,script))
		result=stdout.read()
		ssh.close()
		return result
	except Exception as e:
		pass
	return {}

def getScriptNums():
	current_path=os.getcwd()
	f=open("%s/jixianjiancha/check/script.txt"%current_path,'r')
	result=[line.strip("\r").strip("\n").strip() for line in f.readlines()]
	return len(result),result

#删除远程服务器上的脚本
def deleteScript(ip,user,password):
	try:
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(ip, 22, username=user, password=password, timeout=200)
		stdin, stdout, stderr=ssh.exec_command("pwd")
		path=stdout.read().strip("\n")
		stdin, stdout, stderr=ssh.exec_command("rm -rf jixianjiancha*")
		ssh.close()
		return True
	except Exception as e:
		return False

