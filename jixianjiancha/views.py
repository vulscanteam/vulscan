#coding=utf-8
from __future__ import unicode_literals
from django.http import JsonResponse
import paramiko
from django.shortcuts import render
from django.shortcuts import HttpResponse
import commands
import re
import time
import json
import executeScript
import ast
import os
import time
import sys
# Create your views here.

from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from jixianjiancha import models
import logging
reload(sys)
sys.setdefaultencoding('gbk')


def log(l,content):
	logging.basicConfig(level=logging.ERROR,
			format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
			datefmt='%a, %d %b %Y %H:%M:%S',
			filename='/home/chenran01/log/jixianjiancha.log',
			filemode='a+')
	console = logging.StreamHandler()
	console.setLevel(logging.ERROR)
	formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
	console.setFormatter(formatter)
	logging.getLogger('').addHandler(console)
	if(l=="error"):
		print l,content
		logging.error(content)
	elif(l=="info"):
		logging.info(content)
	else:
		logging.debug(content)
	logging.getLogger('').removeHandler(console)

def executesql(sql,save_database): #将数据插入数据库
	#cur.execute('CREATE TABLE `baseCheck` (`id` INTEGER PRIMARY KEY,`ip` varchar(30) ,`time` datetime ,`checkpoint` varchar(100) ,`level` varchar(20) ,`suggestion` varchar(200) ,`describe` varchar(200) )')
	if(save_database=="baseCheck"):
		models.BaseCheck.objects.create(**sql)
	elif(save_database=="process"):
		models.Process_save.objects.create(**sql)
	'''mysql 链接
	db = MySQLdb.connect("10.95.54.9", "bobac", "bobac_sec!", "vulscan", charset='utf8' )
	# 使用cursor()方法获取操作游标 
	cursor = db.cursor()
	cursor.execute(sql)
	db.commit()
	cursor.close()
	'''
def analysisScript(result,ip,time,save_database):#解析扫描后的结果，结果为json形式
	rows=result['rows']
	keys=result.keys()
	checkpoint=""
	for p in keys:
		if(p!="rows"):
			checkpoint=p
	for c in result[checkpoint].keys():
		level=""
		suggestion=""
		describe=""
		if(c==''):
			describe=result[checkpoint][c]['describe']
		else:
			describe=str(c)+":"+str(result[checkpoint][c]['describe'])
		level=result[checkpoint][c]['level']
		suggestion=result[checkpoint][c]['repair']
		sql={'ip':ip,'time':time,'checkpoint':checkpoint,'suggestion':suggestion,'level':level,'describe':describe}
		#sql='insert into baseCheck (ip,time,checkpoint,suggestion,`level`,`describe`) values ("%s","%s","%s","%s","%s","%s")'%(ip,time,checkpoint,suggestion,level,describe)
		if(result[checkpoint][c]['tag']!=0 or save_database=="process"):
			executesql(sql,save_database)


def index(request):
	context={}
	context['hello'] = 'Hello World!'
	return render(request, 'test.html', context)

@csrf_exempt
def check(request):
	context ={}
	ip= request.POST.get("ip")
	username= request.POST.get("username")
	password= request.POST.get("password")
	context = {"ip":ip,"username":username,"password":password,"result":False}
	#ippattern="(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)$"
	#if(re.match(ippattern,ip)):
	testip=ip.split(".")
	if(testip[0].isdigit() and testip[1].isdigit() and testip[2].isdigit()and testip[3].isdigit()):
		pass
	else:
		context['error']="ip格式不正确"
		log("error","[-]%s ip is error"%(str(ip)))
		print("[-]%s ip格式不正确"%(ip))
		#return render(request, 'test.html', context)
		return HttpResponse(json.dumps(context),content_type="application/json")
	try:
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(ip, 22, username=username, password=password, timeout=100)
		log("info","[*]%s %s %s username password is right"%(str(ip),str(username),str(password)))
		print ("[*]%s %s %s 帐号密码正确"%(ip,username,password))
		ssh.close()
	except Exception as e:
		print e
		context['error']="帐号密码错误"
		log("error","[-]%s %s %s :username password is error"%(ip,username,password))
		print ("[-]%s %s %s :帐号密码错误"%(ip,username,password))
		return HttpResponse(json.dumps(context,content_type="application/json"))

	try:
		if(executeScript.transRemote(ip,username,password)):
			context['result']=True
			length,scripts=executeScript.getScriptNums()
			context["scriptLength"]=length
			log("info","[+]%s Upload unzip script success"%(ip))
			print ("[+]%s 上传解压脚本成功"%(ip))
			current_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
			context["time"]=current_time
			
			#向数据库中添加扫描次数
			sql={'ip':ip,'time':current_time}
			models.Scan_number.objects.create(**sql)
			return HttpResponse(json.dumps(context),content_type="application/json")
		else:
			context['result']=False
			context['error']="解压或上传脚本出错了"
			log("error","[-]%s Upload unzip script failure"%(ip))
			print ("[-]%s 上传解压脚本失败"%(ip))
			return HttpResponse(json.dumps(context),content_type="application/json")
		
	except Exception as e:
		log("error","[-]%s Upload unzip script failure"%(ip))
		print ("[-]%s 上传解压脚本失败"%(ip))
		context['error']="解压或上传脚本出错"
		
	return HttpResponse(json.dumps(context),content_type="application/json")

@csrf_exempt
def execute(request):
	context ={}

	ip= request.POST.get("ip")
	username= request.POST.get("username")
	password= request.POST.get("password")
	idnex= int(request.POST.get("index"))
	current_time=request.POST.get("time")
	context = {"ip":ip,"username":username,"password":password,"result":False}
	#ippattern="(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)$"
	#if(re.match(ippattern,ip)):
	testip=ip.split(".")
	if(testip[0].isdigit() and testip[1].isdigit() and testip[2].isdigit()and testip[3].isdigit()):
		pass
	else:
		context['error']="ip格式不正确"
		log("error","[-]%s ip is error"%(ip))
		print ("[-]%s ip格式不正确"%(ip))
		#return render(request, 'test.html', context)
		return HttpResponse(json.dumps(context),content_type="application/json")

	try:
		length,scripts=executeScript.getScriptNums()
		if(idnex>length or idnex<1):
			context['error']="脚本索引值错误"
			log("error","[-]%s %s %s Script index value error"%(ip,str(length),str(index)))
			print ("[-]%s %s %s 脚本索引值错误"%(ip,str(length),str(index)))
			return HttpResponse(json.dumps(context),content_type="application/json")
		
		script=scripts[idnex-1]
		#判断是否是端口扫描
		if("port_scan" in script):
			current_path=os.getcwd()
			payload="python %s//jixianjiancha/check/%s %s"%(current_path,script,ip)
			commandResult=commands.getoutput(payload)
			result=ast.literal_eval(commandResult)
			analysisScript(result,ip,current_time,"baseCheck")
			log("info","[+]%s Port scan save in database"%(ip))
			context['exploit']=result
			context['result']=True
			log("info","[+]%s Port scan completion"%(ip))
			print ("[+]%s 端口扫描完成"%(ip))
			return HttpResponse(json.dumps(context),content_type="application/json")
		
		result=executeScript.remote_ssh(ip,username,password,script)
			
		result=ast.literal_eval(result)
		context['exploit']=result
		context['result']=True

		#判断是否是读取远程进程
		save_database="baseCheck"
		if("process" in script):
			save_database="process"
		analysisScript(result,ip,current_time,save_database)
		log("info","[+]%s %sscript save in database"%(ip,script))
		log("info","[+]%s %s Script execution completion"%(ip,script))
		print ("[+]%s %s 脚本执行完成"%(ip,script))
		return HttpResponse(json.dumps(context),content_type="application/json")
	except Exception as e:
		print e
		log("error","[-]%s %s Script execution failure"%(ip,script))
		print ("[-]%s %s 脚本执行失败"%(ip,script))
		context['error']="%s脚本执行失败"%(script)
	return HttpResponse(json.dumps(context),content_type="application/json")


@csrf_exempt
def delete(request):
	context ={}
	
	ip= request.POST.get("ip")
	username= request.POST.get("username")
	password= request.POST.get("password")
	context = {"ip":ip,"username":username,"password":password,"result":False}
	#ippattern="(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)$"
	#if(re.match(ippattern,ip)):
	testip=ip.split(".")
	if(testip[0].isdigit() and testip[1].isdigit() and testip[2].isdigit()and testip[3].isdigit()):
		pass
	else:
		context['error']="ip格式不正确"
		log("error","[-] %s ip is error"%(ip))
		print ("[-] %s ip格式不正确"%(ip))
		#return render(request, 'test.html', context)
		return HttpResponse(json.dumps(context),content_type="application/json")

	try:
		if(executeScript.deleteScript(ip,username,password)):
			log("info","[+] %s File deleting on a remote server"%(ip))
			print ("[+] %s 远程服务器上文件删除成功"%(ip))
			return HttpResponse(json.dumps(context),content_type="application/json")
	except Exception as e:
		context['error']="远程服务器上文件删除失败"
		log("error","[-] %s File deletion failure on a remote server"%(ip))
		print ("[-] %s 远程服务器上文件删除失败"%(ip))
	return HttpResponse(json.dumps(context),content_type="application/json")



	