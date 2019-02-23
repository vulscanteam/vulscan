#coding=utf-8
from django.shortcuts import render

from django.http import HttpResponse
from django.conf import settings

#导入公共函数库
from appscan.function import *

#导入数据库模型
from plug.models import spider,spider_conf

#爬虫首页
def index(request):
    #获取爬虫结果
    tables = spider.objects.all()
    #获取爬虫表单配置
    form_conf = {}
    db_conf = spider_conf.objects.all()
    if db_conf:
        form_conf = spider_conf.objects.all()[0]
    else:
        form_conf['keyword']=''
        form_conf['exec_sousuo']=''
        form_conf['page_sousuo']=''
        form_conf['quanzhong_vaule']=''
    #渲染poc列表
    data = poc_list.objects.all()
    return render(request,'spider.html',{'tables':tables,'form_conf':form_conf,'data':data,})

#爬虫表单处理
def spider_action(request):
    if request.POST:
        keyword = request.POST['keyword'] #搜索关键词 
        exec_sousuo = request.POST['exec_sousuo'] #搜索引擎命令
        page_sousuo = int(request.POST['page_sousuo']) #搜索页数
        quanzhong_vaule = request.POST['quanzhong_vaule'] #爱站权重
        chongfu_check = request.POST['chongfu_check'] #是否去重
        chongfu_check = request.POST['chongfu_check'] #是否去重
        vul_id = request.POST['vulid'] #获取扫描的POC

        #保存爬虫表单参数配置
        spider_conf.objects.all().delete()
        spider_conf.objects.create(keyword=keyword,exec_sousuo=exec_sousuo,page_sousuo=page_sousuo,quanzhong_vaule=quanzhong_vaule)

        word = keyword + "  " + exec_sousuo #汇总搜索关键词参数
        #定义爬虫进度
        global spider_jindu
        #page_sousuo = 100
        for i in xrange(1,page_sousuo):  
            spider_jindu = int((float(i+1)/float(page_sousuo))*100) #转化为整数百分比
            #time.sleep(1) # 调试显示进度效果
            #下面开始执行搜索操作
            #print "run_spider++++++++",word,i,quanzhong_vaule,chongfu_check,vul_id,""
            run_spider(word,i,quanzhong_vaule,chongfu_check,vul_id)
        else:
            #pass 结束后返回1,避免报错,结束 可以刷新页面显示结果 或者 清空重置页面表单
            #spider_jindu=0
            return HttpResponse(1)
        #return HttpResponse(spider_jindu)
    else:
        return render(request,'spider.html',)

#爬虫ajax进度
def get_jindu(request):
    try:
        return HttpResponse(spider_jindu)
    except:
        #当没有进度时，返回 0
        return HttpResponse("0")

#搜索关键词 和 搜索页数
def run_spider(word = 'inurl:.php?id',page = 1 ,quanzhong = 1,chongfu = 1,vul_id=1):
    baseUrl = 'http://www.baidu.com/s'
    data = "?wd="+word+"&pn="+str(page-1)+"0"+"&tn=baidurt&ie=utf-8&bsst=1"
    #获取url信息
    try:
        html = requests.get(url=baseUrl+data,headers = headers,verify=False).content
        #print html
    except:
        pass
    #读取加载url
    soup = BS(html,'lxml')
    td = soup.find_all(class_='f')
    #查找百度快照结果树
    for t in td:
        link_url = t.h3.a['href']
        #核心调试用 print link_url
        
        #判断是否重复域名
        if repeated(link_url):
        #判断权重是否大于quanzhong，大于quanzhong则写入文件
            rank = int(get_rank(link_url)) 
            print link_url,"========================================================",rank
            if rank >= int(quanzhong):
                #判断是否有漏洞
                if scan_poc(link_url,vul_id):
                    #写入数据库
                    spider.objects.create(url=link_url,aizhan=rank,vulid=vul_id)
                else:
                    #没有漏洞
                    pass
            else:
                #权重小于1，不写入
                pass
        else:
            #重复了，不做处理
            #print "url repeated :",link_url 
            pass

#判断数据库中是否存在该域名
def repeated(url):
    try:
        domain = re.findall(r"^http://.*?\?{1}",url,re.I)[0] #获取 http://domain.com/index.php?
    except:
        #print "get domain error!",url
        return False
    #正则匹配域名，判断数据库中是否存在
    result = spider.objects.filter(url__iregex="^"+domain)
    if len(result) > 0:
        return False #重复
    else:
        return True


#获取爱站百度权重
def get_rank(url):
    try:
        baseUrl = "http://baidurank.aizhan.com/"
        siteurl = re.findall(r"^http://.*?/{1}",url,re.I)[0].replace('http://','').replace('/','')  
        html = requests.get(baseUrl + siteurl).content
        #解决延迟加载问题
        #time.sleep(5)
        #print baseUrl + siteurl,html
        #exit()
        soup = BS(html,'lxml')

        #新的获取权重正则
        div = soup.find_all('div',class_='ip')
        rank = str(div[0]).replace('\t','').replace('\n','').replace(' ','')
        results = re.findall(r"(\d)\.png",rank,re.I)[-1]
        #print results

        #div = soup.find('div',class_='mb10').find_all('td')
        #rank = str(div[1]).replace('\t','').replace('\n','').replace(' ','')
        #results = re.findall(r"(\d)\.gif",rank,re.I)[-1]
    except Exception ,e:
        print e,'get_rank error!'
        #get_rank(url) #如果网站打不开就不要了,返回0
        return 0

    #判断是否获取到权重，未获取到重新获取
    if results:
        return results
    else:
        print 'get rank error!',url
        get_rank(url)

#下载结果集
def show_tables(request):
    tables = spider.objects.all()
    data =""
    for results in tables:
        data = data + str(results.url) + "\n"#"<br>"
    #print data
    response = HttpResponse(data)
    response['Content-Type'] = 'application/octet-stream'
    response['Content-Disposition'] = 'attachment;filename="urls.txt"'
    return response

#清空结果集
def delete_tables(request):
    result_del = spider.objects.all().delete()
    global spider_jindu
    spider_jindu = 0
    #删除会 返回 删除的条数
    #print result_del
    #删除成功后返回1
    return HttpResponse(1)

#删除 一个url记录
def delete_url(request,vid):
    res = spider.objects.get(id=vid).delete()
    return HttpResponse(1)



"""
待解决问题：

1.权重配置 动态装入；== ok
2.一键清空数据库结果；== ok
3.通过 权重排序显示
4.发送到其他模块
5.解决前端bug问题
6.增加多线程扫描
"""