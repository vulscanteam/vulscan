#coding=utf-8
from django.shortcuts import render

# Create your views here.
from django.contrib import auth #authenticate,login,logout
#from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect

#@login_required   # 验证单一一个模块是否登录用

def login(request):
    #判断是否登陆
    if request.user.is_authenticated():
        return HttpResponseRedirect('/')

    #登陆提交
    if request.method == 'POST':
        #获取表单用户密码
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        #获取的表单数据与数据库进行比较
        user = auth.authenticate(username = username,password = password)
        if user is not None and user.is_active:
            #比较成功，跳转index
            auth.login(request,user)
            request.session['username'] = username
            return HttpResponseRedirect('/')
        else:
            #比较失败，还在login
            return render(request, 'login.html')
    else:
        return render(request, 'login.html')

def logout(request):
    auth.logout(request)
    return HttpResponseRedirect('/login/')

