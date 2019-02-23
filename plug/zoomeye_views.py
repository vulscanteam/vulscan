#coding=utf-8
from django.shortcuts import render

from django.http import HttpResponse,HttpResponseRedirect
from django.conf import settings

#导入数据库模型
from plug.models import zoomeye_host,zoomeye_web
#导入公共函数库
from appscan.function import *

#api文档
#https://www.zoomeye.org/api/doc#search-filters


#zoomeye首页和处理表单
def index(request):
    if request.method == 'GET':
      tables_host = zoomeye_host.objects.all()
      tables_web = zoomeye_web.objects.all()
      #渲染poc列表
      data = poc_list.objects.all()
      return render(request,'zoomeye.html',{'tables_host':tables_host,'tables_web':tables_web,'data':data,})
    elif request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        query = request.POST['query'] #搜索关键词 
        page = request.POST['page'] #搜索页数
        facets = request.POST['facets'] #搜索过滤器
        sousuo_type = request.POST['sousuo_type'] #搜索类型
        vulid = request.POST['vulid'] #搜索类型
        #处理表单
        res = zoomeye_action(username,password,query,page,facets,sousuo_type,vulid)
        ##
        return HttpResponse(res)
        
    else:
        raise Http404()

#获取api类型
def api_type(get_type):
    #GET /host/search
    #GET /web/search
    api = "https://api.zoomeye.org/"
    curr_api = api + str(get_type) + "/search"
    return curr_api

#登陆请求API,获取access_token
def login(username,password):
  data = {
      'username' : username, #配置用户名
      'password' : password, #配置密码
  }
  data_encoded = json.dumps(data)# dumps 将 python 对象转换成 json 字符串
  try:
      r = requests.post(url = 'https://api.zoomeye.org/user/login',data = data_encoded)
      r_decoded = json.loads(r.text) # loads() 将 json 字符串转换成 python 对象
      access_token = r_decoded['access_token']
      print  u"login success: ",access_token
      headers = {'Authorization' : 'JWT ' + str(access_token),} 
      return headers
  except Exception,e:
      print '[-] info : username or password is wrong, please try again '
      exit()

#清洗host数据
def api_host(json_result,vulid):
  for value in json_result['matches']:
    ip=str(value['ip']) #ip
    city=str(value['geoinfo']['city']['names']['en']) #城市
    hostname=str(value['portinfo']['hostname']) #主机名
    port=str(value['portinfo']['port']) #端口号
    os_version=str(value['portinfo']['os']+value['portinfo']['version']) #操作系统和版本
    device=str(value['portinfo']['device']) #设备类型
    #判断是否重复ip写入数据库
    print ip
    result = zoomeye_host.objects.filter(ip=ip)
    if (len(result) == 0) and (scan_poc(ip,vulid)):#不重复且存在漏洞
      #写入数据库
      zoomeye_host.objects.create(ip=ip,city=city,hostname=hostname,port=port,os_version=os_version,device=device,vulid=vulid,)


#清洗web数据
def api_web(json_result,vulid):
  for value in json_result['matches']:
    #print value
    ip=str(value['ip'][0]) #ip
    city=str(value['geoinfo']['city']['names']['en']) #城市
    
    #捕获异常
    try:
      server=str(value['server'][0]['name']) #服务器名称
    except Exception, e:
      server = ""
    #捕获异常
    try:    
    	db=str(value['db'][0][u'name']) #数据库
    except Exception, e:
      db = ""    	
    webapp=str(value['webapp'][0]['name']) #应用名称
    site=str(value['site']) #网址
    #判断是否重复ip写入数据库
    result = zoomeye_host.objects.filter(ip=ip)
    if (len(result) == 0) and (scan_poc(ip,vulid)):#不重复且存在漏洞
      #写入数据库
      zoomeye_web.objects.create(ip=ip,city=city,server=server,db=db,webapp=webapp,site=site,vulid=vulid,)

#清空host数据
def delete_tables_host(request):
    result_del = zoomeye_host.objects.all().delete()
    return HttpResponse('success delete host!')
#清空web数据
def delete_tables_web(request):
    result_del = zoomeye_web.objects.all().delete()
    return HttpResponse('success delete web!')

#处理删掉一条数据
#
#
#

#处理表单方法
def zoomeye_action(username,password,query,page,facets,sousuo_type,vulid):
    #获取api请求方式
    api_base = api_type(str(sousuo_type))
    #获取授权
    headers = login(username,password)

    #循环获取,如果搜索页数超过实际权限页数,则搜索最大页数
    for i in xrange(1,int(page)+1): 
        #拼接请求参数
        api_url = api_base + "?"  + "query="+str(query)+"&facets="+str(facets)+"&page="+str(i)
        #处理结果
        html = requests.get(url=api_url,headers=headers).content
        result = json.loads(html)
        #print result,"======================="
        try:
            if str(sousuo_type) == "host":
              api_host(result,vulid)
              res = "HOST获取数据成功!"+str(i)+"页"
            elif str(sousuo_type) == "web":
              api_web(result,vulid)
              res =  "WEB获取数据成功!"+str(i)+"页"
            else:
              res =  '数据获取失败1!'
        except Exception ,e:
            import traceback
            traceback.print_exc()
            res =  "数据获取失败2!"
            return res
    else:
        return res

