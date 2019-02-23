#coding=utf-8
#导入公共函数库
from function import *
#导入数据库模型,判断poc是否需要升级
from django.core import serializers
from appscan import models

#一键扫描
vulscan_object = {}
def index(request):
    global vulscan_object 
    url = request.GET['url']
    token = request.GET['token']  
    action = request.GET['action'] 
    list_renwu = []

    #API 不记录扫描记录和漏洞记录
    if action == "index":
        #根据本地保存的poc扫描，不从数据库获取poc
        for filename in  LIST_FILE:
            list_renwu.append({'url':url.strip(),"poc":filename.strip()}) 
        #实例化扫描类
        #vulscan_object = webscan(list_renwu)
        #vulscan_object.run()
        #list_report = vulscan_object.list_report
        vulscan_object[token] = webscan(list_renwu)
        vulscan_object[token].run()
        list_report = vulscan_object[token].list_report   
        return HttpResponse(list_report)
    #ajax 实时返回扫描进度
    elif action == "jindu":
        try:
            num = int(vulscan_object[token].vulscan_jindu)
            report = vulscan_object[token].list_report
            return HttpResponse(num)
        except Exception as e:
             #当没有进度时，返回 0，此时会抛出异常，这里没做异常处理直接print e了
             #print e
             return HttpResponse("0")
    elif action == "report":
        try:
            response = HttpResponse(json.dumps(vulscan_object[token].list_report))
            response['Content-Type'] = 'application/json'
            #response['Content-Type'] = 'application/octet-stream'
            #response['Content-Disposition'] = 'attachment;filename="result.json"'
            return response
        except Exception, e:
            #raise e
            return HttpResponse("0")
    else:
        return HttpResponse("0")




""" api
一键扫描接口：http://127.0.0.1:8000/api?action=index&url=127.0.0.1&token=api
扫描进度接口：http://127.0.0.1:8000/api?action=jindu&url=127.0.0.1&token=api
json接口报告：http://127.0.0.1:8000/api?action=report&url=127.0.0.1&token=api
"""
