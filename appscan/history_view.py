#coding=utf-8
from appscan import models
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from function import *
from db import scan_in_db,vul_in_db,update_db

#用户漏洞历史状态标识
def index(request):
    output = []
    if request.method == "GET":
        username = request.user.username
        vul_list = models.vul_scan.objects.values('url').filter(username=username).order_by("url").distinct()
        print vul_list
        for d_url in vul_list:
            print d_url
            url = d_url['url']
            # print url
            r_list = models.vul_state.objects.all().filter(url=url).filter(state=u'未修复')
            # print r_list
            for i in r_list:
                vulname = i.vulname
                vulid = models.poc_list.objects.get(name=vulname).vulID
                cvss = i.cvss
                output.append([url, vulname, cvss, vulid])

        # output = json.dumps(output)
        print output
        p = Paginator(output, 10, )
        page = request.GET.get('page', 1)
        try:
            nums = p.page(page)
        except PageNotAnInteger:
            nums = p.page(1)
            # 使用Pagination进行分页（10个一页）
        except EmptyPage:
            # If page is out of range (e.g. 9999), deliver last page of results.
            nums = p.page(p.num_pages)
            print 'out of page!'
        print nums
        print p.page_range
        # numlist = [i for i in p.page_range][int(page)-3:int(page)+2]
        div_num = 5
        for i in  p.page_range:
            if int(page)-3 < 0:
                numlist = [i for i in p.page_range][:div_num]
            elif int(page)+2 > p.num_pages:
                numlist = [i for i in p.page_range][int(p.num_pages)-div_num:int(p.num_pages)]
            else:
                numlist = [i for i in p.page_range][int(page) - (div_num-2):int(page) + (div_num-3)]


        print numlist
        return render(request, 'history.html', {'nums': nums,'numlist':numlist})
    else:

        return HttpResponse('error')
#忽略漏洞
def ignore(request):
    if request.GET:
        url = request.GET['url']
        vulname = request.GET['vulname']
        result = models.vul_state.objects.filter(url=url).filter(vulname=vulname)
        if result.exists():
            result.update(state=u'已忽略')
    return HttpResponse(1)
#验证所有历史漏洞
def rescan_all(request):
    if request.method == "GET":
        output = []
        username = request.user.username
        vul_list = models.vul_scan.objects.values('url').filter(username=username).distinct()
        # print vul_list
        for d_url in vul_list:
            # print d_url
            url = d_url['url']

            # print url
            r_list = models.vul_state.objects.all().filter(url=url).filter(state=u'未修复')
            # print r_list
            for i in r_list:
                vulname = i.vulname
                vulid = models.poc_list.objects.get(name=vulname).vulID
                cvss = i.cvss
                pocname = models.poc_list.objects.get(name=vulname).filename
                output.append([url, pocname, cvss, vulid])
        # print output
        for i in output:
            file = open(os.path.join(BASE_DIR, i[1]))
            info = {'pocstring': file.read(),
                    'pocname': i[1]
                    }
            file.close()
            cn = TestApi(i[0], info)
            try:
                list_report = []
                result = cn.run()
                # print result
                if result[5][1] == "success":
                    # print "is vul"
                    # print result[7]
                    # 增加漏洞风险等级字段

                    str_list = list(result)  # 元组转换列表
                    # print type(str_list)
                    pocname_str_list = list(str_list[1].encode("utf-8"))
                    pocname_str_list.insert(-2, '.')
                    # print pocname_str_list
                    pocname_str_list = "".join(pocname_str_list).decode("utf-8")
                    str_list[1] = pocname_str_list
                    str_list[5] = 'success'

                    result = tuple(str_list)

                    result = result + (i[2],)

                    # print result
                    list_report.append(result)
                    print list_report
                    # 存数据库
                    vul_in_db(username, list_report)
                else:
                    # print "not vul"
                    # 去数据库查询，若曾经有漏洞则更新漏洞状态
                    update_db(url, i[3])
            except Exception, e:
                print e
                return HttpResponse(0)  # False
        return HttpResponse(1)



