#!/usr/bin/env python
# coding=utf-8
from email.MIMEText import MIMEText  
from email.Utils import formatdate  
from email.Header import Header  
from function import *
import smtplib

def send_mail(session,report):
    #写入数据库记录
    print len(report)
    msg = []
    for i in report:
        url = i[0]
        poc = i[1]
        appname = i[3]
        version = i[4]
        date = i[6]
        cvss = i[8].decode('utf-8')
        msg.append({'URL': url, 'poc': poc, u'应用名称': appname, u'影响版本': version, u'扫描时间': date, u'漏洞等级': cvss})
        #写入数据库
        # obj = models.vul_scan(username=session, appname=appname, url=url, pocname=poc, date=date, cvss=cvss)
        # obj.save()    
    if len(report) > 0:
        #vul_in_db(session, appname, url, poc, cvss)
        #vul_in_db(session,report)
        #发送邮件内容
        data = '本次扫描已结束，扫描人：%s, 扫描地址为 %s。 其中共发现%d 个漏洞' % (session, url, len(report))
        #发送邮件标题
        subject = u'[vulscan]' + msg[0]['URL'] + u'-扫描结果' 
    else:
        #发送邮件内容
        data = '本次扫描已结束，未发现漏洞。扫描人：%s' % session
        #发送邮件标题
        subject = u'[vulscan]' + u'  * -扫描结果'        

    #初始化邮件  
    try:  
        sender = '10000@qq.com'  #发送邮箱地址
        receiver = '610358898@qq.com'    #接受邮箱地址
        smtpserver = 'smtp.qq.com'      #邮局服务器
        username = '10000'        #用户名
        password = '***********'           #密码    
        msg = MIMEText(data,'html','utf-8')     
        msg['Subject'] = subject      
        smtp = smtplib.SMTP()  
        smtp.connect('smtp.qq.com')  
        smtp.login(username, password)  
        smtp.sendmail(sender, receiver, msg.as_string())  
        smtp.quit()   
    except Exception as e:
        print '[-]error!'
        raise e  
