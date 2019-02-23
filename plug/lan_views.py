#coding=utf-8

#导入公共函数库
from appscan.function import *
#导入数据库模型
from appscan.models import poc_list

#C段扫描首页
def index(request):
    data = poc_list.objects.all()
    return render(request,'lan.html',{'data':data,})

#提交扫描处理
def lan_scan(request):
    #初始化 全局变量
    global report
    report = []
    #任务列表 和 扫描进度
    global list_renwu 
    global c_jindu
    c_jindu = 0
    #计时器
    global i
    i = 0

    #定义全局钩子 c段结果
    global c_report
    c_report = []
       
    #c_jindu = 0
    url = request.GET['url']
    vul_id = request.GET['vulid']
    #获取漏洞数据库信息
    poc = poc_list.objects.get(vulID=vul_id) #poc.filename
    #获取C段ip列表,任务数
    list_renwu = ip_c(url,vul_id)

    """ 改写取得列表位置
    ip_list = ['127.0.0.1','127.0.0.2','127.0.0.3']
    for i in ip_list:
      print i

    for i in xrange(len(ip_list)):
      print ip_list[i]
    """
    
    """
    #遍历检测C段POC
    for i in xrange(len(ip_list)):
        #获取扫描进度
        c_jindu = int((float(i+1)/float(len(ip_list)))*100) #转化为整数百分比
        #print c_jindu
        #print ip_list[i]
        report_vul = scan_poc(ip_list[i],vul_id)
    """
    #定义线程池 默认20线程
    pool = threadpool.ThreadPool(20) 

    #迭代任务队列
    requests = threadpool.makeRequests(scan_poc,list_renwu) 
    for req in requests:
        pool.putRequest(req)
    pool.wait() 
            
    #增加扫描结束标识
    report.append({
                'vul':'0', #前端js判断结束时,不刷新
                'url':'检测完毕',
                'report':'检测完毕',
            })
    #print report
    return HttpResponse(json.dumps(report))
    #return HttpResponse("report")

#ajax 实时返回扫描结果
def lan_json(request):
    try:
        return HttpResponse(json.dumps(report),content_type="application/json")
    except:
        #当没有进度时，返回 0
        return HttpResponse("0")

#ajax 实时返回扫描进度
def scan_jindu(request):
    try:
        return HttpResponse(c_jindu)
    except Exception, e:
        print e
        #当没有进度时，返回 0
        return HttpResponse("0")

#ajax 返回扫描结果
def scan_report(request):
    #response = HttpResponse(json.dumps(report))
    #response['Content-Type'] = 'application/octet-stream'
    #response['Content-Disposition'] = 'attachment;filename="c_result.json"'
    #return response
    #c_report
    try:
        return render(request,'report.html',{'data':c_report,})
    except Exception, e:
        print e
        #当没有进度时，返回 0
        return HttpResponse("没有结果")

#生成C段ip
def ip_c(ip,vuid):
    try:
        ip = socket.getaddrinfo(ip, None)[0][4][0]
        result_ip =[]
        starts = ip.split('.')
        A = int(starts[0])
        B = int(starts[1])
        C = int(starts[2])
        D = int(starts[3])
        #生成A、B段 则增加ip循环
        for D in range(1,255): #255
            ip = "%d.%d.%d.%d" %(A,B,C,D)
            result_ip.append({'ip':ip,'vuid':vuid})
        return result_ip        
    except Exception, e:
        result_ip = []
        return result_ip
    
#调用pocvulid 扫描
def scan_poc(ip_list):
    global report
    global c_jindu
    global c_report
    #拆分字段获取参数
    ip = ip_list['ip']
    vid= ip_list['vuid']
    #
    queueLock.acquire()  
    global i
    i+=1
    #print "===============",i,"=============="
    c_jindu = int((float(i+1)/float(len(list_renwu)))*100) #转化为整数百分比
    #print scan_jindu,"%"
    queueLock.release()
    #    
    #检测poc
    poc = poc_list.objects.get(vulID=vid) #poc.filename
    file = open(os.path.join(BASE_DIR,poc.filename))
    info = { 'pocstring': file.read(),
             'pocname': poc.filename
            }
    file.close()
    #print info,ip
    cn = TestApi(ip, info)

    try:
        #调试用的代码,pocsuite排错
        res = cn.get_info()
        #print res.vulID,res.name

        result = cn.run()
        #print result
        if result[5][1] == "success" :
            #print "is vul"
            #sprint result[7]
            test = eval(result[7])
            #print test['VerifyInfo']['Payload']
            #report_vul['payload'] = test['VerifyInfo']['Payload']
            report_vul = cgi.escape(test['VerifyInfo']['Payload'])
            #记录所有结果
            
            #增加漏洞风险等级字段
            result = result + (poc.cvss,)
            
            c_report.append(result)
        else:
            #print "not vul"
            #return HttpResponse(0) #False
            report_vul = {}
    except Exception, e:
        #print e
        #return HttpResponse(0) #False
        report_vul = {}
    #print type(report_vul)

    #判断如果有结果
    if report_vul:
        #print ip_list[i],vul_id,report_json
        report_json = {
            'vul':poc.filename,
            'url':ip,
            'report':report_vul,
        }
        report.append(report_json)
        #report_json["ip"] = ip_list[i]
        #report_json["payload"] = report_vul    
    return report
