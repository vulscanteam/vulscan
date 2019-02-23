# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


import sys  
reload(sys)  
sys.setdefaultencoding('utf8')
# Create your models here.

class BaseCheck(models.Model):
	vid=models.IntegerField(primary_key=True) #主键
	ip=models.CharField(max_length=255,null=True,blank=True)#扫描ip
	time=models.CharField(max_length=255,null=True,blank=True)#扫描时间
	checkpoint=models.CharField(max_length=255,null=True,blank=True)#检查项
	level=models.CharField(max_length=255,null=True,blank=True)#漏洞等级
	suggestion=models.CharField(max_length=255,null=True,blank=True)#修复建议
	describe=models.CharField(max_length=255,null=True,blank=True)#漏洞描述

class Process_save(models.Model):
	vid=models.IntegerField(primary_key=True) #主键
	ip=models.CharField(max_length=255,null=True,blank=True)#扫描ip
	time=models.CharField(max_length=255,null=True,blank=True)#扫描时间
	describe=models.TextField()#进程描述
	checkpoint=models.CharField(max_length=255,null=True,blank=True)#检查项
	level=models.CharField(max_length=255,null=True,blank=True)#漏洞等级
	suggestion=models.CharField(max_length=255,null=True,blank=True)#修复建议

class Scan_number(models.Model):
	vid=models.IntegerField(primary_key=True) #主键
	ip=models.CharField(max_length=255,null=True,blank=True)#扫描ip
	time=models.CharField(max_length=255,null=True,blank=True)#扫描时间
