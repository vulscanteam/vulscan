#coding=utf-8
from django.shortcuts import render
from appscan.function import *
# Create your views here.
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

def index(request):
    try:
        action = request.GET['action'] 
        url = request.GET['url'] 
        if action == "get_web_server":
            print get_web_server(url)
            return HttpResponse(get_web_server(url))
        elif action == "get_web_site":
            print get_web_site(url)
            return HttpResponse(get_web_site(url))
    except Exception, e:
        #raise e
        return render(request,'fingerprint.html',)


#web服务节点接口
def get_web_server(url):
    result = []
    site_address_api = "http://ce.baidu.com/index/CheckSite?site_address="
    try:
        json_html = json.loads(requests.get(url=site_address_api+url).text)
        web_service = json_html['data']['detail_report']['env']['check_types'][0]['check_items']
        for i in xrange(0,len(web_service),1):
            #print web_service[i]['name'],":",web_service[i]['result']
            result.append({"key":web_service[i]['name'],"vaule":web_service[i]['result'],})
    except Exception, e:
        #raise e
        result=[{'',''},]
    return json.dumps(result)

#关联站点
def get_web_site(url):
    list_domain = []
    related_address_api = "http://ce.baidu.com/index/getRelatedSites?site_address="
    related_service = json.loads(requests.get(url=related_address_api+url).text)['data']
    for domain in related_service:
        list_domain.append(domain['domain'])
    print list_domain
    return json.dumps(list_domain)