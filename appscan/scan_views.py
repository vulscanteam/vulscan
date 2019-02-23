#coding=utf-8

#导入公共函数库
from function import *
#导入数据库模型
from appscan.models import poc_list
from appscan.models import user_scan
from views import *
#from mail import send_mail
from db import scan_in_db,vul_in_db,update_db


#统计数据库漏洞数量 和 本地存在漏洞数量
#当不一致的时候自动更新POC漏洞库
#如果相等返回 true, 不相等返回 false
#更新POC后要重启下 django
def judge(request):
    #数据库中存放POC的数量统计
    db_coutn = poc_list.objects.count()
    #本地存放POC的统计
    file_count = len(LIST_FILE)
    #print db_coutn,file_count
    if int(db_coutn) == int(file_count) :
        return True
    else :
        return False


#POC插件列表
def index(request):
    #判断是否需要更新
    if not judge(request):
        #更新操作
        updata(request)
        #return HttpResponse(u"update")
        #pass
    #显示页面
    if request.method == 'GET':
        #from django.core import serializers
        data = poc_list.objects.all()
        #data = serializers.serialize("json", poc_list.objects.all())
        #json解析到前端显示数据
        #return render(request,'scan.html',{"list_data":json.dumps(data),}) #data,content_type="application/json"
        return render(request,'scan.html',{'data':data,})
    else :
        return HttpResponse(u"error!!!")

    #return render(request,'scan.html')
    
#验证POC页面信息
def vulid(request,vulid):
    poc = poc_list.objects.filter(vulID=vulid)
    #print help(poc)
    #return HttpResponse(vulid)
    return render(request,'scan_vulid.html',{'poc':poc,})

#验证POC调用
def poc_scan(request):
    #hook result
    global list_report
    list_report = []
    if request.GET:
        #获取检测的id和url
        vul_id = request.GET['id']
        url = request.GET['url']
        session = request.user.username
        #获取id 对应的文件名
        poc = poc_list.objects.get(vulID=vul_id) #poc.filename
        file = open(os.path.join(BASE_DIR,poc.filename))
        info = { 'pocstring': file.read(),
                 'pocname': poc.filename
                }
        file.close()
        cn = TestApi(url, info)
        
        #保存扫描记录
        scan_in_db(session, url)
        try:
            result = cn.run()
            #print result
            if result[5][1] == "success" :
                #print "is vul"
                #print result[7]
                #增加漏洞风险等级字段
                #result = result + (poc.cvss,)
                #list_report.append(result)
                #print list_report

                #增加pocsuitejson报告文件名缺少.问题 1-redis-getshell.py , 1-redis-getshellpy
                str_list = list(result) #元组转换列表
                # print type(str_list)
                pocname_str_list = list(str_list[1].encode("utf-8"))
                pocname_str_list.insert(-2,'.')
                # print pocname_str_list
                pocname_str_list = "".join(pocname_str_list).decode("utf-8")
                str_list[1] = pocname_str_list
                str_list[5] = 'success'
                result = tuple(str_list)
                result = result + (poc.cvss,)
                
                print result
                list_report.append(result)
                print list_report

                #存数据库
                vul_in_db(session, list_report)
                #发送邮件
                return HttpResponse(1) #True
            else:
                #print "not vul"
                #去数据库查询，若曾经有漏洞则更新漏洞状态
                update_db(url, vul_id)
                return HttpResponse(0) #False
            #send_mail(request,list_report)
        except Exception, e:
            print e
            #traceback.print_exc()
            return HttpResponse(0) #False
    #return HttpResponse(0)


#更新本地到数据库的 poc插件列表
def updata(request):
    #遍历取得文件列表
    for filename in  LIST_FILE:
        file = open(os.path.join(BASE_DIR,filename))
        info = { 'pocstring': file.read(),
                 'pocname': filename
                }
        #print filename
        #info.update(mode='verify') #默认不用添加
        cn = TestApi("http://test.com", info)
        res = cn.get_info()
        #print res.vulID,res.vulDate,res.name,res.author,res.vulType
        #判断是否重复id写入数据库
        result = poc_list.objects.filter(vulID=res.vulID)
        if len(result) == 0:#不重复
          #写入数据库
            poc_list.objects.create(
                appName=res.appName,
                appPowerLink=str(res.appPowerLink),
                appVersion=str(res.appVersion),
                author=res.author,
                createDate=res.createDate,
                desc=res.desc,
                install_requires=str(res.install_requires),
                name=res.name,
                references=str(res.references),
                samples=str(res.samples),
                updateDate=res.updateDate,
                version=str(res.version),
                vulID=int(res.vulID),
                vulType=str(res.vulType),
                cvss = str(res.cvss),
                filename=str(filename),
            )
    #更新完毕后跳转到首页
    #return HttpResponse(u"更新完毕!")


#ajax 实时返回扫描结果
def vulid_report(request):
    try:
        #return HttpResponse(json.dumps(list_report),content_type="application/json")
        return render(request,'report.html',{'data':list_report,})
    except Exception, e:
        print e
        #当没有进度时，返回 0
        return HttpResponse("没有结果")


#远程判断poc是否需要更新和下载等相关操作
def test_poc_list(request):
    pass    



#手动分类，新增加的POC,需要自己手动 分类