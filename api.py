# -*- coding: utf-8 -*-

import sys,os
import re
import json
from pocsuite.api.cannon import Cannon
from pocsuite.lib.core.data import kb

#配置漏洞目录
VUL_DIR = 'vul'
#获取当前目录
BASE_DIR = os.path.join(os.getcwd(),VUL_DIR)
#加载POC文件目录,对象不能动态刷新
#POC_FILE = os.walk(BASE_DIR)
LIST_FILE = os.listdir(BASE_DIR)

#获取POC信息 继承接口类
class TestApi(Cannon):
    #获取POC信息
    def get_info(self):
        #动态模块名
        poc = kb.registeredPocs[self.moduleName]
        #注册类后,需要释放类
        if self.delmodule:
            delModule(self.moduleName)
        #返回类信息
        return poc


#与django对接数据库ORM



"""
#遍历取得文件列表
for path,dirlist,filelist in POC_FILE:
    for filename in filelist:
        file = open(os.path.join(path,filename))
        info = { 'pocstring': file.read(),
                 'pocname': filename
                }
        #info.update(mode='verify')
        cn = TestApi("http://127.0.0.1", info)
        res = cn.get_info()
        print res.vulID,res.vulDate,res.name,res.author,res.vulType

        
        appName #应用名称
        appPowerLink #官网连接
        appVersion #影响版本
        author #编写作者
        createDate #创建时间
        desc #漏洞描述
        install_requires #依赖库
        name #英文漏洞名称
        references #漏洞来源
        samples = #漏洞实例
        updateDate #更新时间
        version #版本信息
        vulDate #漏洞时间
        vulID #漏洞ID
        vulType #漏洞类型
        cvss #漏洞等级
"""        

#演示API获取接口
def get_demo():
    for filename in   LIST_FILE:
        #print filename  
        #print os.path.join(BASE_DIR,filename)   
        file = open(os.path.join(BASE_DIR,filename))     
        info = { 'pocstring': file.read(),
                 'pocname': filename
                }
        file.close()
        #info.update(mode='verify')
        cn = TestApi("http://127.0.0.1", info)
        res = cn.get_info()
        print os.path.join(BASE_DIR,filename)
        print res.vulID,res.vulDate,res.name,res.author,res.vulType,res.cvss


#测试获取结果，实时生成报告 pyh
def test(url = "127.0.0.1"):
    for filename in   LIST_FILE:
        #print filename  
        #print os.path.join(BASE_DIR,filename)   
        file = open(os.path.join(BASE_DIR,filename))     
        info = { 'pocstring': file.read(),
                 'pocname': filename
                }
        file.close()
        #info.update(mode='verify')
        cn = TestApi(url, info)
        try:

            #调试用的代码,pocsuite排错
            res = cn.get_info()
            print res.vulID,res.name

            result = cn.run()
            #print result
            if result[5][1] == "success" :
                #print "is vul"
                #sprint result[7]
                test = eval(result[7])
                print test['VerifyInfo']['Payload']
                #return HttpResponse(1) #True
            else:
                #print "not vul"
                #return HttpResponse(0) #False
                pass
        except Exception, e:
            print e
            #return HttpResponse(0) #False
            pass

#POC生成json,效验更新
def poctojson():
    result = []
    for filename in   LIST_FILE:
        #print filename  
        #print os.path.join(BASE_DIR,filename)   
        file = open(os.path.join(BASE_DIR,filename))     
        info = { 'pocstring': file.read(),
                 'pocname': filename
                }
        file.close()
        
        #info.update(mode='verify')
        cn = TestApi("", info)
        res = cn.get_info()
        print res.vulID,res.vulDate,res.name,res.desc
        vul_dic = {
            'vulID':res.vulID,
            'vulDate':res.vulDate,
            'name':res.name,
            'desc':res.desc,
        }
        result.append(vul_dic)

    print json.dumps(result)    
    return json.dumps(result)


with open('updata.json','w') as f:
    f.write(poctojson())

