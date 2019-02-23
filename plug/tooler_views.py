#coding=utf-8
from django.shortcuts import render
from django.http import HttpResponse

import requests,urllib,base64,hashlib

def index(request):
    if request.method == 'GET':
        old = u"hello world!"
        new = u"hello%20world%21"
        return render(request,'tooler.html',{'old':old,'new':new,})
    elif request.method == 'POST':
        try:
            #判断处理方式
            #return HttpResponse(requests)
            #获取表单值并设置编码
            old  = request.POST['old'] .encode('utf-8')
            action = request.POST['action'] 

            if action == 'urlencode':
                new = urllib.quote(old)
            elif action == 'urldecode':
                new = urllib.unquote(old)   
            elif action == 'asciicode':
                ascii_code = ''
                for i in range(len(old)):
                    ascii_code = ascii_code + u'chr(' + str(ord(old[i])).strip() + u')' 
                #中文部分会存在问题
                new = ascii_code
            elif action == 'enbase64':
                new = base64.encodestring(old)
            elif action == 'debase64':
                new = base64.decodestring(old)
            elif action == 'enmd5':
                passwd = hashlib.md5()
                passwd.update(old)
                new = passwd.hexdigest()
            else:
                return HttpResponse('error!')
            return render(request,'tooler.html',{'old':old,'new':new,})
            #以上可能会出现异常操作，未做异常处理/
        except:
            return HttpResponse('error!')

"""
def tooler(request):
    if not request.POST:
        #判断第一次加载，无数据则显示模板
        #return HttpResponse('2222')
        old = u"hello world!"
        new = u"hello%20world%21"
        return render(request,'tooler.html',{'old':old,'new':new,})
    else :
        #判断处理方式
        #return HttpResponse(requests)
        #获取表单值并设置编码
        old  = request.POST['old'] .encode('utf-8')
        action = request.POST['action'] 

        if action == 'urlencode':
            new = urllib.quote(old)
        elif action == 'urldecode':
            new = urllib.unquote(old)   
        elif action == 'asciicode':
            ascii_code = ''
            for i in range(len(old)):
                ascii_code = ascii_code + u'chr(' + str(ord(old[i])).strip() + u')' 
            #中文部分会存在问题
            new = ascii_code
        elif action == 'enbase64':
            new = base64.encodestring(old)
        elif action == 'debase64':
            new = base64.decodestring(old)
        elif action == 'enmd5':
            passwd = hashlib.md5()
            passwd.update(old)
            new = passwd.hexdigest()
        else:
            return HttpResponse('error!')
        return render(request,'tooler.html',{'old':old,'new':new,})
        #以上可能会出现异常操作，未做异常处理/
"""