#coding=utf-8
#
#导入公共函数库
from function import *
#导入数据库模型,判断poc是否需要升级
from django.core import serializers
from appscan import models
from mail import send_mail
from db import scan_in_db,vul_in_db,update_db


#配置服务端api
api_version = settings.UPDATE_POC['poc_api'] + "/version/" #程序版本
api_poc_list = settings.UPDATE_POC['poc_api'] + "/poc_list_json/" #poc列表

#定义保存用户状态的字典
vulscan_object = {}
#是否发邮件
is_send_mail = True

def index(request):
    #返回5条
    poc_data = models.poc_list.objects.values('vulID','desc','references','name',).order_by("-vulID")[0:5]
    #获取poc来源,漏洞分析
    poc_referer = []
    for poc in poc_data:
        #print poc['references'] #.replace('[','').replace('\'','').replace(']','').replace(',','')
        if len(poc['references']):
            url = poc['references'].replace('[','').replace('\'','').replace(']','').replace(',','')
            poc_referer.append(url)

    #获取程序版本号
    #客户端版本号
    client_version = settings.UPDATE_POC['version']
    #服务端版本号
    try:
        server_version = requests.get(url = api_version ,timeout=5).text
    except Exception, e:
        server_version = client_version
    # print request.user.username
    #页面扫描地址
    try:
        global vulscan_object
        session = request.user.username
        url = vulscan_object[session].url
    except:
        url = "http://test.com"
    #渲染模版标签
    return render(request, 'index.html',{
        'poc_data':poc_data,
        'poc_referer':poc_referer,
        'client_version':client_version,
        'server_version':server_version,
        'url':url,
        })

#验证是否需要更新,返回需要更新的漏洞id和名称,数量
def update(request):
    #定义要返回的列表
    result = []
    #print settings.UPDATE_POC,settings.UPDATE_POC['poc_api'],settings.UPDATE_POC['version']
    #获取服务端json
    try:
        api_json = json.loads(requests.get(api_poc_list).content)
        #print api_json
        #遍历json对象
        for poc in api_json :
            #print poc["fields"]["name"],"vulID:"+str(poc["pk"]),
            value = {"vulID":str(poc["pk"]),"name":poc["fields"]["name"],}
            #数据库查询是否存在这个poc
            api_result = models.poc_list.objects.filter(vulID=poc["pk"])
            if len(api_result) == 0:#不存在
                #需要更新的poc
                #print "no no no"
                result.append(value)
            else:
                #不需要更新
                #print "yes"
                pass
    except Exception,e:
        #print e
        #result = []
        pass
    if len(result)>0:
        #print "update",result
        return HttpResponse(json.dumps(result))
    else:
        #print "no update"
        return HttpResponse()


#生成本地poclist以json返回,
def poc_list_json(request):
    data = models.poc_list.objects.all()
    #print help(data.__dict__) #内置数据库对象 转为 字典类型
    #获取数据库的poc列表
    #print local_json
    response_json = serializers.serialize("json", data)
    #print response_json
    return HttpResponse(response_json)


    """
    |  appName = <django.db.models.query_utils.DeferredAttribute object>
    |  appPowerLink = <django.db.models.query_utils.DeferredAttribute object>
    |  appVersion = <django.db.models.query_utils.DeferredAttribute object>
    |  author = <django.db.models.query_utils.DeferredAttribute object>
    |  category = <django.db.models.query_utils.DeferredAttribute object>
    |  createDate = <django.db.models.query_utils.DeferredAttribute object>
    |  desc = <django.db.models.query_utils.DeferredAttribute object>
    |  filename = <django.db.models.query_utils.DeferredAttribute object>
    |  install_requires = <django.db.models.query_utils.DeferredAttribute object>
    |  name = <django.db.models.query_utils.DeferredAttribute object>
    |  objects = <django.db.models.manager.Manager object>
    |  references = <django.db.models.query_utils.DeferredAttribute object>
    |  samples = <django.db.models.query_utils.DeferredAttribute object>
    |  updateDate = <django.db.models.query_utils.DeferredAttribute object>
    |  version = <django.db.models.query_utils.DeferredAttribute object>
    |  vulID = <django.db.models.query_utils.DeferredAttribute object>
    |  vulType = <django.db.models.query_utils.DeferredAttribute object>
    """

#客户端和服务端重用api
def version(request):
    version = settings.UPDATE_POC['version']
    return HttpResponse(version) 

#检查程序是否需要更新
def main_version(request):
    #客户端版本号
    client_version = settings.UPDATE_POC['version']
    #服务端版本号
    try:
        server_version = requests.get(api_version).text
    except Exception:
        server_version = client_version
    
    #print str(client_version),str(server_version)
    if str(client_version) == str(server_version):
        #如果是1,不更新
        update = '1'
    else:
        #如果是0,更新
        update = '0'
    return HttpResponse(update)

#版本说明
def help(request):
    return render(request,'help.html')

#一键扫描
def vulscan(request):
    global vulscan_object 
    list_renwu = []
    url = request.GET['url']
    """ 取主URL
    if ':' in url and len(url.split(':')) > 2: #https://wwww.baidu.com:443
        url = url.split(':')[0] + ":" + url.split(':')[1]
        #https://www.baidu.com
    elif ':' in url and len(url.split(':')) == 2 and 'http' not in url: #127.0.0.1:8888
        url = url.split(':')[0]
        #127.0.0.1
    print url
    """
    #获取当前用户 
    session = request.user.username
    #写入数据量扫描记录
    scan_in_db(session, url)
    #根据本地保存的poc扫描，不从数据库获取poc
    for filename in  LIST_FILE:
        list_renwu.append({'url':url.strip(),"poc":filename.strip()}) 
    vulscan_object[session] = webscan(list_renwu)
    print vulscan_object
    vulscan_object[session].run()
    list_report = vulscan_object[session].list_report
    #处理扫描报告
    print '-----------report------------'
    #记录扫描报告
    vul_in_db(session,list_report)
    #处理发邮件
    if is_send_mail :
        send_mail(session, list_report)
        print "send mail ok"
    return HttpResponse(list_report)

#ajax 实时返回扫描结果
def vulscan_report(request):
    global vulscan_object
    session = request.user.username
    #print session
    try:
        #return HttpResponse(json.dumps(list_report),content_type="application/json")
        return render(request,'report.html',{'data':vulscan_object[session].list_report,})
    except Exception, e:
        # print e
        #当没有进度时，返回 0
        return HttpResponse("没有结果")

#ajax 实时返回扫描进度
def vulscan_jindu(request):
    global vulscan_object
    session = request.user.username
    print u'当前用户',session
    try:
        print u'当前进度',vulscan_object[session].vulscan_jindu
        num = int(vulscan_object[session].vulscan_jindu)
        report = vulscan_object[session].list_report
        return HttpResponse(num)
    except Exception as e:
         #当没有进度时，返回 0，此时会抛出异常，这里没做异常处理直接print e了
         print e
         return HttpResponse("0")

#ajax 返回扫描结果
def vulscan_json(request):
    global vulscan_object
    session = request.user.username
    response = HttpResponse(json.dumps(vulscan_object[session].list_report))
    response['Content-Type'] = 'application/json'
    #response['Content-Type'] = 'application/octet-stream'
    #response['Content-Disposition'] = 'attachment;filename="result.json"'
    # print list_report
    return response

#漏洞分析
def analysis(request):
    data = models.poc_list.objects.all()
    return render(request,'analysis.html',{'data':data,})





