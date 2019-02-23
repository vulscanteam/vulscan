#coding=utf-8

#导入公共函数库
from function import *
#导入数据库模型
from appscan.models import navigation,navigation_url
# Create your views here.
import sys
reload(sys)
sys.setdefaultencoding("utf-8")
def index(request):
    #navigation = navigation.objects.fiter('你的条件')
    #data = navigation_url.objects.all()
    result = []
    fenlei = navigation.objects.all()
    #print len(fenlei)
    for key in range(1,len(fenlei)+1) :
        print (fenlei[key-1]).__str__,">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"

    for key in range(0,len(fenlei)+1) :
        #print str(fenlei[key]).decode("utf-8").encode("gbk")
        #反向查找
        test = navigation_url.objects.filter(nav_name_id=key).all()
        #print test,len(test)
        #for i in test:
        #    print i.nav_name,i.nav_title,i.nav_url

        #key-1 排除掉第一次查询,不为空时再处理
        if len(test):
            data = {
            'fenlei_name':fenlei[key-1], #.encode('gbk').decode(),
            'fenlei_url':test
            }
            #print data
            result.append(data)

    #print result
    return render(request,'navigation.html',{'data':result,})

    #return HttpResponse('success')