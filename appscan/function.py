#coding=utf-8

#常用库引用
import urllib
import urllib2
import re
import requests
import time
import socket
import os
import cgi
import json
from bs4 import BeautifulSoup as BS
import threading
import threadpool 
#weakpass lib
import ftplib
import hashlib
import struct
import binascii
import telnetlib
import array

import smtplib
#刷新显示
import sys
reload(sys)
sys.setdefaultencoding( "utf-8" )

#django response库 
from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.conf import settings
from appscan.models import poc_list

headers={      "User-Agent":"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.152 Safari/537.36",
                "Accept":"*/*",
                "Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                "Accept-Encoding":"gzip, deflate",
                "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With":"XMLHttpRequest",
                "Connection":"keep-alive"
        }


# pocsuite api 公共配置接口
#配置漏洞目录
VUL_DIR = settings.VUL_DIR
#获取当前目录
BASE_DIR = settings.BASE_DIR
#加载POC文件目录
LIST_FILE = settings.LIST_FILE

#引入pocsuite
from pocsuite.api.cannon import Cannon
from pocsuite.lib.core.data import kb
#获取POC信息 继承接口类
class TestApi(Cannon):
    #获取POC信息
    def get_info(self):
        #动态模块名
        #poc = kb.registeredPocs[self.moduleName]
        #注册类后,需要释放类
        if self.delmodule:
            delModule(self.moduleName)
        poc = kb.registeredPocs[self.moduleName]
        #返回类信息
        return poc

#定义线程锁
queueLock = threading.Lock()

#weakpass弱口令扫描类
class weakpass():
    def __init__(self,url,server):
        self.url = url
        #获取ip和端口号
        url_split = re.split(":",self.url)
        self.ip = url_split[0]
        self.port = int(url_split[1])
        #
        self.server = server
        self.return_result = [] #返回 服务类型,地址,账户,密码
        #{'server':str(self.server),'url':str(self.url),'u':str(user),'p':str(pass_),}
        
    def run(self,user,pass_):
        #ip和port都存在
        if self.ip and self.port:
            #如果ip和端口都存在
            if self.server == "mysql":
                self.mysql(user,pass_)
            elif self.server == "ftp":
                self.ftp(user,pass_)
            elif self.server == "postgresql":
                self.postgresql(user,pass_)            
            elif self.server == "redis":
                self.redis(user,pass_)    
            elif self.server == "mssql":
                self.mssql(user,pass_) 
            elif self.server == "telnet":
                self.telnet(user,pass_)
            else:
                pass

    def ftp(self,user,pass_):
        ftp = ftplib.FTP()
        try:
            ftp.connect(self.ip,self.port)
            ftp.login(user,pass_)
            if user == 'ftp':self.return_result.append({'server':str(self.server),'url':str(self.url),'u':"",'p':"",}) # return "anonymous"
            #return "username:%s,password:%s"%(user,pass_)
            self.return_result.append({'server':str(self.server),'url':str(self.url),'u':str(user),'p':str(pass_),})
        except Exception,e:
            pass
        finally:
            ftp.close()
    def mysql(self,user,pass_):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.ip,self.port))
            packet = sock.recv(254)
            plugin,scramble = self.get_scramble(packet)
            if not scramble:return 3
            auth_data = self.get_auth_data(user,pass_,scramble,plugin)
            sock.send(auth_data)
            result = sock.recv(1024)
            if result == "\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00":
                self.return_result.append({'server':str(self.server),'url':str(self.url),'u':str(user),'p':str(pass_),})
                #return "username:%s,password:%s" % (user,pass_)
        except:
            pass
        finally:
            sock.close()
    def postgresql(self,user,pass_):#author:hos@YSRC
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.ip,self.port))
            packet_length = len(user) + 7 +len("\x03user  database postgres application_name psql client_encoding UTF8  ")
            p="%c%c%c%c%c\x03%c%cuser%c%s%cdatabase%cpostgres%capplication_name%cpsql%cclient_encoding%cUTF8%c%c"%( 0,0,0,packet_length,0,0,0,0,user,0,0,0,0,0,0,0,0)
            sock.send(p)
            packet = sock.recv(1024)
            if packet[0]=='R':
                authentication_type=str([packet[8]])
                c=int(authentication_type[4:6],16)
                if c==5:salt=packet[9:]
                else:return 3
            else:return 3
            lmd5= self.make_response(user,pass_,salt)
            packet_length1=len(lmd5)+6
            pp='p%c%c%c%c%s%c'%(0,0,0,packet_length1 - 1,lmd5,0)
            sock.send(pp)
            packet1 = sock.recv(1024)
            if packet1[0] == "R":
                self.return_result.append({'server':str(self.server),'url':str(self.url),'u':str(user),'p':str(pass_),})
                #return "username:%s,password:%s" % (user,pass_)
        except Exception,e:
            return 3
        finally:
            sock.close()
    def redis(self,user,pass_):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((self.ip,int(self.port)))
            s.send("INFO\r\n")
            result = s.recv(1024)
            if "redis_version" in result:
                self.return_result.append({'server':str(self.server),'url':str(self.url),'u':"",'p':"",}) #return "unauthorized"
            elif "Authentication" in result:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self.ip,self.port))
                s.send("AUTH %s\r\n"%(pass_))
                result = s.recv(1024)
                if '+OK' in result:
                    #return "username:%s,password:%s" % (user,pass_)
                    self.return_result.append({'server':str(self.server),'url':str(self.url),'u':"",'p':str(pass_),})
        except Exception,e:
            return 3
        finally:
            s.close()
    def mssql(self,user,pass_):#author:hos@YSRC
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.ip,self.port))
            hh=binascii.b2a_hex(self.ip)
            husername=binascii.b2a_hex(user)
            lusername=len(user)
            lpassword=len(pass_)
            ladd=len(self.ip)+len(str(self.port))+1
            hladd=hex(ladd).replace('0x','')
            hpwd=binascii.b2a_hex(pass_)
            pp=binascii.b2a_hex(str(self.port))
            address=hh+'3a'+pp
            hhost= binascii.b2a_hex(self.ip)
            data="0200020000000000123456789000000000000000000000000000000000000000000000000000ZZ5440000000000000000000000000000000000000000000000000000000000X3360000000000000000000000000000000000000000000000000000000000Y373933340000000000000000000000000000000000000000000000000000040301060a09010000000002000000000070796d7373716c000000000000000000000000000000000000000000000007123456789000000000000000000000000000000000000000000000000000ZZ3360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000Y0402000044422d4c6962726172790a00000000000d1175735f656e676c69736800000000000000000000000000000201004c000000000000000000000a000000000000000000000000000069736f5f31000000000000000000000000000000000000000000000000000501353132000000030000000000000000"
            data1=data.replace(data[16:16+len(address)],address)
            data2=data1.replace(data1[78:78+len(husername)],husername)
            data3=data2.replace(data2[140:140+len(hpwd)],hpwd)
            if lusername>=16:
                data4=data3.replace('0X',str(hex(lusername)).replace('0x',''))
            else:
                data4=data3.replace('X',str(hex(lusername)).replace('0x',''))
            if lpassword>=16:
                data5=data4.replace('0Y',str(hex(lpassword)).replace('0x',''))
            else:
                data5=data4.replace('Y',str(hex(lpassword)).replace('0x',''))
            hladd = hex(ladd).replace('0x', '')
            data6=data5.replace('ZZ',str(hladd))
            data7=binascii.a2b_hex(data6)
            sock.send(data7)
            packet=sock.recv(1024)
            if 'master' in packet:
                #return "username:%s,password:%s" % (user,pass_)
                self.return_result.append({'server':str(self.server),'url':str(self.url),'u':str(user),'p':str(pass_),})
        except:
            return 3
        finally:
            sock.close()
    def telnet(self,user,pass_):
        try:
            tn = telnetlib.Telnet(self.ip,self.port)
            #tn.set_debuglevel(3)
            time.sleep(0.5)
            os = tn.read_some()
        except Exception ,e:
            return 3
        user_match="(?i)(login|user|username)"
        pass_match='(?i)(password|pass)'
        login_match='#|\$|>'
        if re.search(user_match,os):
            try:
                tn.write(str(user)+'\r\n')
                tn.read_until(pass_match,timeout=2)
                tn.write(str(pass_)+'\r\n')
                login_info=tn.read_until(login_match,timeout=3)
                tn.close()
                if re.search(login_match,login_info):
                    #return "username:%s,password:%s" % (user,pass_)
                    self.return_result.append({'server':str(self.server),'url':str(self.url),'u':str(user),'p':str(pass_),})
            except Exception,e:
                pass
        else:
            try:
                info=tn.read_until(user_match,timeout=2)
            except Exception,e:
                return 3
            if re.search(user_match,info):
                try:
                    tn.write(str(user)+'\r\n')
                    tn.read_until(pass_match,timeout=2)
                    tn.write(str(pass_)+'\r\n')
                    login_info=tn.read_until(login_match,timeout=3)
                    tn.close()
                    if re.search(login_match,login_info):
                        self.return_result.append({'server':str(self.server),'url':str(self.url),'u':str(user),'p':str(pass_),})
                        #return "username:%s,password:%s" % (user,pass_)
                except Exception,e:
                    return 3
            elif re.search(pass_match,info):
                tn.read_until(pass_match,timeout=2)
                tn.write(str(pass_)+'\r\n')
                login_info=tn.read_until(login_match,timeout=3)
                tn.close()
                if re.search(login_match,login_info):
                    #return "password:%s" % (pass_)
                    self.return_result.append({'server':str(self.server),'url':str(self.url),'u':"",'p':str(pass_),})
    def get_hash(self,password, scramble):
        hash_stage1 = hashlib.sha1(password).digest()
        hash_stage2 = hashlib.sha1(hash_stage1).digest()
        to = hashlib.sha1(scramble+hash_stage2).digest()
        reply = [ord(h1) ^ ord(h3) for (h1, h3) in zip(hash_stage1, to)]
        hash = struct.pack('20B', *reply)
        return hash
    def get_scramble(self,packet):
        scramble,plugin = '',''
        try:
            tmp = packet[15:]
            m = re.findall("\x00?([\x01-\x7F]{7,})\x00", tmp)
            if len(m)>3:del m[0]
            scramble = m[0] + m[1]
        except:
            return '',''
        try:
            plugin = m[2]
        except:
            pass
        return plugin,scramble
    def get_auth_data(self,user,password,scramble,plugin):
        user_hex = binascii.b2a_hex(user)
        pass_hex = binascii.b2a_hex(self.get_hash(password,scramble))
        data = "85a23f0000000040080000000000000000000000000000000000000000000000" + user_hex + "0014" + pass_hex
        if plugin:data+=binascii.b2a_hex(plugin)+ "0055035f6f73076f737831302e380c5f636c69656e745f6e616d65086c69626d7973716c045f7069640539323330360f5f636c69656e745f76657273696f6e06352e362e3231095f706c6174666f726d067838365f3634"
        len_hex = hex(len(data)/2).replace("0x","")
        auth_data = len_hex + "000001" +data
        return binascii.a2b_hex(auth_data)
    def make_response(self,username,password,salt):
        pu=hashlib.md5(password+username).hexdigest()
        buf=hashlib.md5(pu+salt).hexdigest()
        return 'md5'+buf    



#一键扫描类
class webscan(weakpass):
    def __init__(self,list_renwu):
        self.list_report = []
        self.list_renwu = list_renwu
        self.vulscan_jindu = 0
        self.i = 0
        self.url = ''
        # self.user = user

    #一键扫描
    def run(self):
        #默认为10线程扫描
        pool = threadpool.ThreadPool(10) 

        #迭代任务队列
        requests = threadpool.makeRequests(self.call_scan,self.list_renwu) 
        print 'add pool ok'
        for req in requests:
            pool.putRequest(req)
            print '---------------------ok----------------------'
        pool.wait() 
        print '---------------------done--------------------'
    #处理单个扫描任务记录进度
    def call_scan(self,renwu):
        self.vulscan_poc(renwu['url'],renwu['poc']) 
        queueLock.acquire()
        self.i+=1 
        print "===============",self.i,"=============="
        self.vulscan_jindu = int((float(self.i)/float(len(self.list_renwu)))*100) #转化为整数百分比
        print  self.i, self.vulscan_jindu,"%"
        queueLock.release()
   

        #扫描任务,阻塞了,单线程
               
    #url通过文件名调用poc
    def vulscan_poc(self,url,filename):
        file = open(os.path.join(BASE_DIR,filename))
        #print file
        info = { 'pocstring': file.read(),
                 'pocname': filename
                }
        file.close()
        #print filename
        #info.update(mode='verify') #默认不用添加
        self.url = url
        cn = TestApi(url, info)   
        #获取poc info,不改pocsuite 返回 report 模版,通过类成员字段获取 漏洞风险等级     
        info = cn.get_info()
        # print info.vulID,info.appName
        try:
            result = cn.run()
            #print result
            if result[5][1] == "success" :
                #print "is vul"
                #print type(result),result
                #test = eval(result[7])
                #return HttpResponse(1) #True
                #report = {
                #    'filename':filename,
                #    'Payload':cgi.escape(test['VerifyInfo']['Payload']),
                #    }
                #增加漏洞风险等级字段
                #result = result + (info.cvss,)
                #self.list_report.append(result)

                #增加pocsuitejson报告文件名缺少.问题 1-redis-getshell.py , 1-redis-getshellpy
                str_list = list(result) #元组转换列表
                # print type(str_list)
                pocname_str_list = list(str_list[1].encode("utf-8"))
                pocname_str_list.insert(-2,'.')
                # print pocname_str_list
                pocname_str_list = "".join(pocname_str_list).decode("utf-8")
                str_list[1] = pocname_str_list
                str_list[5] = 'success'
                result = tuple(str_list)
                
                result = result + (info.cvss,)
                self.list_report.append(result)

                return result
            else:
                return 0
        except Exception, e:
            return 0

#单个poc扫描，不回传结果
#传入url和扫描vulid 加载POC判断是否有漏洞
def scan_poc(url,vid):
    #report_vul = {}
    #检测poc
    poc = poc_list.objects.get(vulID=vid) #poc.filename
    file = open(os.path.join(BASE_DIR,poc.filename))
    info = { 'pocstring': file.read(),
             'pocname': poc.filename
            }
    file.close()
    #print info,url
    cn = TestApi(url, info)
    try:
        #调试用的代码,pocsuite排错
        res = cn.get_info()
        #print res.vulID,res.name
        result = cn.run()
        #print result
        if result[5][1] == "success" :
            #print "is vul"
            #sprint result[7]
            test = eval(result[7])
            #print test['VerifyInfo']['Payload']
            #report_vul['payload'] = test['VerifyInfo']['Payload']
            report_vul = cgi.escape(test['VerifyInfo']['Payload'])
        else:
            #print "not vul"
            #return HttpResponse(0) #False
            report_vul = {}
    except Exception, e:
        #print e
        report_vul = {}
    #判断如果有结果
    if report_vul:  
        return True
    else:
        return False
#
