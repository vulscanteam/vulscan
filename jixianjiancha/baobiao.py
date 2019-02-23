#coding=utf-8
from __future__ import unicode_literals
from django.http import JsonResponse
import paramiko
from django.shortcuts import render
from django.shortcuts import HttpResponse
# Create your views here.
import datetime, time,sys
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from jixianjiancha.models import BaseCheck
from jixianjiancha.models import Scan_number
from django.db.models import Count


reload(sys)
sys.setdefaultencoding('gbk')

@csrf_exempt
def month(request):
	response = {}
	end_time = datetime.datetime.now().date()
	month_begin_time = end_time -datetime.timedelta(days=30)

	month_vuls = BaseCheck.objects.filter(time__gte=month_begin_time).filter(time__lte=end_time).count()
	month_scan = Scan_number.objects.filter(time__gte=month_begin_time).filter(time__lte=end_time).count()
	month_cvss_yanzhong = BaseCheck.objects.filter(time__gte=month_begin_time).filter(time__lte=end_time).filter(level=u'严重').count()
	month_cvss_gaowei = BaseCheck.objects.filter(time__gte=month_begin_time).filter(time__lte=end_time).filter(level=u'高危').count()
	month_cvss_zhongwei = BaseCheck.objects.filter(time__gte=month_begin_time).filter(time__lte=end_time).filter(level=u'中危').count()

	paiming = BaseCheck.objects.values('checkpoint').annotate(num_poc=Count('checkpoint')).order_by('num_poc')

	response['month_scan'] = month_scan #月扫描数
	response['month_vuls'] = month_vuls	 #月漏洞数
	
	response['month_cvss_yanzhong'] = month_cvss_yanzhong
	response['month_cvss_gaowei'] = month_cvss_gaowei
	response['month_cvss_zhongwei'] = month_cvss_zhongwei
	response['paiming'] = paiming


	return render(request, 'baobiao_monthly.html', response)

@csrf_exempt
def week(request):
	response = {}
	end_time = datetime.datetime.now().date()
	month_begin_time = end_time -datetime.timedelta(days=7)

	month_vuls = BaseCheck.objects.filter(time__gte=month_begin_time).filter(time__lte=end_time).count()
	month_scan = Scan_number.objects.filter(time__gte=month_begin_time).filter(time__lte=end_time).count()
	month_cvss_yanzhong = BaseCheck.objects.filter(time__gte=month_begin_time).filter(time__lte=end_time).filter(level=u'严重').count()
	month_cvss_gaowei = BaseCheck.objects.filter(time__gte=month_begin_time).filter(time__lte=end_time).filter(level=u'高危').count()
	month_cvss_zhongwei = BaseCheck.objects.filter(time__gte=month_begin_time).filter(time__lte=end_time).filter(level=u'中危').count()

	paiming = BaseCheck.objects.values('checkpoint').annotate(num_poc=Count('checkpoint')).order_by('num_poc')

	response['month_scan'] = month_scan #月扫描数
	response['month_vuls'] = month_vuls	 #月漏洞数
	
	response['month_cvss_yanzhong'] = month_cvss_yanzhong
	response['month_cvss_gaowei'] = month_cvss_gaowei
	response['month_cvss_zhongwei'] = month_cvss_zhongwei
	response['paiming'] = paiming
	return render(request, 'baobiao_week.html', response)
