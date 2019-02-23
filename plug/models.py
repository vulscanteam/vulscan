# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.


#爬虫结果
class spider(models.Model):
    url = models.CharField(max_length=255) #固定字符
    aizhan = models.IntegerField() #整型 ， models.TextField() #文本
    vulid = models.CharField(max_length=255) # 漏洞类型

    def __unicode__(self):
    	return self.url

#爬虫配置
class spider_conf(models.Model):
    keyword = models.CharField(max_length=255) # 关键词
    exec_sousuo = models.CharField(max_length=255,null=True,blank=True) # 搜索命令,可用为空
    page_sousuo = models.IntegerField(default=100) # 搜索页数
    quanzhong_vaule = models.IntegerField(default=1) # 爱站权重

#zoomeye结果host
class zoomeye_host(models.Model):
    ip = models.CharField(max_length=255,null=True,blank=True) #ip
    city = models.CharField(max_length=255,null=True,blank=True) #城市
    hostname = models.CharField(max_length=255,null=True,blank=True) #主机名
    port = models.CharField(max_length=255,null=True,blank=True) #端口号
    os_version = models.CharField(max_length=255,null=True,blank=True) #操作系统
    device = models.CharField(max_length=255,null=True,blank=True) #设备类型
    vulid = models.CharField(max_length=255) # 漏洞类型

#zoomeye结果web
class zoomeye_web(models.Model):
    ip = models.CharField(max_length=255,null=True,blank=True) #ip
    city = models.CharField(max_length=255,null=True,blank=True) #城市
    server = models.CharField(max_length=255,null=True,blank=True) #服务器名称
    db = models.CharField(max_length=255,null=True,blank=True) #数据库
    webapp = models.CharField(max_length=255,null=True,blank=True) #应用名称
    site = models.CharField(max_length=255,null=True,blank=True) #网址
    vulid = models.CharField(max_length=255) # 漏洞类型