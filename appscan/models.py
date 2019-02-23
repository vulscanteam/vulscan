#coding=utf-8
from __future__ import unicode_literals
from django.db import models

import sys  
reload(sys)  
sys.setdefaultencoding('utf8')   

# Create your models here.

#POCSUITE插件列表
class poc_list(models.Model):
    appName = models.CharField(max_length=255,null=True,blank=True) #应用名称
    appPowerLink = models.CharField(max_length=255,null=True,blank=True) #官网连接
    appVersion = models.CharField(max_length=255,null=True,blank=True) #影响版本
    author = models.CharField(max_length=255,null=True,blank=True) #编写作者
    createDate = models.CharField(max_length=255,null=True,blank=True) #创建时间
    desc = models.TextField() #漏洞描述
    install_requires = models.CharField(max_length=255,null=True,blank=True) #依赖库
    name = models.CharField(max_length=255,null=True,blank=True) #英文漏洞名称
    references = models.CharField(max_length=255,null=True,blank=True) #漏洞来源
    samples = models.CharField(max_length=255,null=True,blank=True) #漏洞实例
    updateDate = models.CharField(max_length=255,null=True,blank=True) #更新时间
    version = models.CharField(max_length=255,null=True,blank=True) #版本信息
    vulID = models.IntegerField(primary_key=True) #漏洞ID,设为主键不允许重复
    vulType = models.CharField(max_length=255,null=True,blank=True) #漏洞类型
    cvss = models.CharField(max_length=255,null=True,blank=True) #漏洞等级
    #文件名
    filename = models.CharField(max_length=255,null=True,blank=True)
    #后台选择分类
    category = models.IntegerField(null=True,blank=True)

#导航分类
class navigation(models.Model):
    nav_name = models.CharField(max_length=255,null=True,blank=True) #分类名称
    #对象转化为字符串显示
    def __unicode__(self): # __str__ , 大坑-https://blog.csdn.net/lmz_lmz/article/details/80088580
        return self.nav_name    

#导航数据
class navigation_url(models.Model):
    nav_name = models.ForeignKey(navigation,related_name="FAN")#models.IntegerField(null=True,blank=True)#分类名称, 外键约束,FAN 反向
    nav_title = models.CharField(max_length=255,null=True,blank=True) #url标题
    nav_url = models.CharField(max_length=255,null=True,blank=True) #url

#漏洞扫描记录
class vul_scan(models.Model):
    username = models.CharField(max_length=255,null=True,blank=True) #扫描人
    appname = models.CharField(max_length=255,null=True,blank=True) #应用名称
    url = models.CharField(max_length=255,null=True,blank=True) #扫描URL
    pocname = models.CharField(max_length=255,null=True,blank=True) #POC名称
    date = models.CharField(max_length=255,null=True,blank=True) #扫描时间
    cvss = models.CharField(max_length=255,null=True,blank=True) #漏洞等级
#用户扫描记录
class user_scan(models.Model):
    username = models.CharField(max_length=255,null=True,blank=True) #扫描人
    url = models.CharField(max_length=255,null=True,blank=True) #扫描URL
    date = models.CharField(max_length=255,null=True,blank=True) #扫描时间

#记录当前用户漏洞状态
class vul_state(models.Model):
    url = models.CharField(max_length=255, null=True, blank=True)  # 扫描URL
    vulname = models.CharField(max_length=255, null=True, blank=True)  # 漏洞名称
    cvss = models.CharField(max_length=255, null=True, blank=True)  # 漏洞等级
    state = models.CharField(max_length=255, null=False, blank=False, default=u'未修复')  # 漏洞状态

