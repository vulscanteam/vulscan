#!/usr/bin/env python
# coding=utf-8
from appscan.models import vul_scan
from appscan.models import user_scan
from appscan.models import vul_state
from appscan.models import poc_list
from function import *

#记录扫描任务
def scan_in_db(username, url):
    date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) 
    obj = user_scan(username=username, url=url, date=date)
    obj.save()
#记录扫描漏洞
def vul_in_db(username, list_report):
    date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    for i in list_report:
        url = i[0]
        pocname = i[1]
        vulname = poc_list.objects.get(filename=pocname).name
        # print name
        appname = i[3]
        cvss = i[8]
        obj = vul_scan(username=username, appname=appname, url=url, pocname=pocname, date=date, cvss=cvss)
        obj.save()
        vul_list = vul_state.objects.all().filter(url=url).filter(vulname=vulname)
        if vul_list.exists():  # 对于url和漏洞查询,存在记录
            if vul_list.filter(state=u'已修复').exists() or vul_list.filter(state=u'已忽略').exists(): #之前状态为已修复，现在需要改为未修复
                vul_list.update(state=u'未修复')
            else: #之前状态就是未修复，不需要操作
                pass
        else: #没有url和漏洞的记录，需要进行插入操作
            obj = vul_state(url=url, vulname=vulname, state=u'未修复', cvss=cvss)
            obj.save()
#更新漏洞状态
def update_db(url, vul_id):
    vulname = poc_list.objects.get(vulID=vul_id).name
    if_fix = vul_state.objects.filter(url=url).filter(vulname=vulname).filter(state=u'未修复').exists()
    if if_fix == False:
        pass
        print 'do nothing'
    else:
        vul_state.objects.filter(url=url).filter(vulname=vulname).update(state=u'已修复')
