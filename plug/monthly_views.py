# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.db.models import Count

from appscan.models import vul_scan
from appscan.models import user_scan
import datetime, time

# Create your views here.
def get_db_info(request):
	response = {}

	end_time = datetime.datetime.now().date()
	
	month_begin_time = end_time -datetime.timedelta(days=30)

	
	
	month_vuls = vul_scan.objects.filter(date__gte=month_begin_time).filter(date__lte=end_time).count()
	month_scan = user_scan.objects.filter(date__gte=month_begin_time).filter(date__lte=end_time).count()
	month_cvss_yanzhong = vul_scan.objects.filter(date__gte=month_begin_time).filter(date__lte=end_time).filter(cvss=u'严重').count()
	month_cvss_gaowei = vul_scan.objects.filter(date__gte=month_begin_time).filter(date__lte=end_time).filter(cvss=u'高危').count()
	month_cvss_zhongwei = vul_scan.objects.filter(date__gte=month_begin_time).filter(date__lte=end_time).filter(cvss=u'中危').count()
	month_cvss_diwei = vul_scan.objects.filter(date__gte=month_begin_time).filter(date__lte=end_time).filter(cvss=u'低危').count()
	
	paiming = vul_scan.objects.values('pocname').annotate(num_poc=Count('pocname')).order_by('num_poc')

	for v in paiming:
		print v
	
		
	#输出
	
	response['month_scan'] = month_scan #月扫描数
	
	response['month_vuls'] = month_vuls	 #月漏洞数
	
	response['month_cvss_yanzhong'] = month_cvss_yanzhong
	response['month_cvss_gaowei'] = month_cvss_gaowei
	response['month_cvss_zhongwei'] = month_cvss_zhongwei
	response['month_cvss_diwei'] = month_cvss_diwei
	response['paiming'] = paiming
	return render(request, 'baobiao_monthly.html', response)