# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.http import HttpResponse
from portscan import *
import nmap
import json

# Create your views here.
nm = {}
#显示扫描页面
def index(request):
    #页面扫描地址
    try:
        global nm
        session = request.user.username
        ip = nm[session].ip
    except:
        ip = ""
    if request.method == 'GET':
        #print 'port ok'
        return render(request,'port.html',{"ip":ip})
    else :
        return HttpResponse("error!!!")
#端口扫描处理报告
def port_scan(request):
    if request.GET:
        global nm 
        session = request.user.username
        host = request.GET['host']
        print '[+]port scan host is: ' + host
        nm[session] = Port(host)
        report_list = nm[session].port_scan()
        
        return HttpResponse(report_list)
    else:
        return HttpResponse("error")
#获取端口扫描状态进度
def get_port_scan_state(request):
    print 'get status'
    global nm 
    session = request.user.username
    try:
        print  "当前端口扫描状态：%s" % nm[session].state
        return HttpResponse(nm[session].state)
    except Exception as e:
        print e
        return HttpResponse('unscan')
#获取端口扫描报告
def get_port_scan_report(request):
    global nm 
    session = request.user.username
    try:
        response = HttpResponse(nm[session].report)
        response['Content-Type'] = 'application/json'
        return response
    except Exception as e:
        print e
        return HttpResponse("No report")

