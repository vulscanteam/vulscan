#coding=utf-8

#导入公共函数库
from appscan.function import *


#配置在字典目录
WEAKPASS = "weakpass"
FILE_WEAKPASS = os.path.join(os.getcwd(),WEAKPASS)

def index(request):
    for root, dirs, files in os.walk(FILE_WEAKPASS): return render(request,'weakpass.html',{"weakpass":files,})
        #print(files) #当前路径下所有非目录子文件 
        #pass

#处理 action 
def call_action(result):
    #print result['u'],result['p']
    global i
    global scan_jindu
    queueLock.acquire()  
    i+=1
    #print "===============",i,"=============="
    scan_jindu = int((float(i+1)/float(len(list_renwu)))*100) #转化为整数百分比
    print scan_jindu,"%"
    queueLock.release()
    #如果没有返回则破解,找到对的账户密码后忽略其他线程,破解多个账户密码需要改 判断条件
    if not len(weakpass_object.return_result):
        #time.sleep(20)
        weakpass_object.run(result['u'],result['p'])
    else:
        pass
        #print "exit"

#处理表单 url,username,password,server,num
def weakpass_run(request):
    url = request.GET['url']
    username = request.GET['username'].replace(' ', '')
    password = request.GET['password'].replace(' ', '')
    server = request.GET['server']
    num = request.GET['num']
    #定义全局队列进度标识
    global i
    i = 0
    #配置扫描进度   
    global scan_jindu
    scan_jindu = 0
    #print os.getcwd()
    weakpass_dict = "weakpass"
    curr_dir = os.getcwd()
    username =  os.path.join(curr_dir,weakpass_dict,username)
    password = os.path.join(curr_dir,weakpass_dict,password)
    print username,password  ### repr
    #定义破解任务列表
    global list_renwu
    list_renwu = []
    #加入队列
    with open(username,"r+") as list_username:
        #print list_username.read()
        for u in list_username.readlines():
            #print username.strip()
            with open(password,"r+") as list_password:
                for p in list_password:
                    #print username.strip(),password.strip()
                    #mysql(username.strip(),password.strip())
                    #pool.run(func=mysql, args=(username.strip(),password.strip()))
                    #assemble.append((username.strip(),password.strip()))
                    #q.put((username.strip(),password.strip()))
                    list_renwu.append({'u':u.strip(),"p":p.strip()})
    #实例化类
    global weakpass_object
    weakpass_object = weakpass(url,server)
    #置空扫描结果
    weakpass_object.return_result = []
    #定义线程池
    pool = threadpool.ThreadPool(int(num)) 
    #任务数
    print len(list_renwu)

    #迭代任务队列
    requests = threadpool.makeRequests(call_action,list_renwu) 
    for req in requests:
        pool.putRequest(req)
    pool.wait() 
    #return weakpass_object.return_result
    return HttpResponse("success")

#返回实时进度
def weakpass_jindu(request):
    try:
        return HttpResponse(scan_jindu)
    except Exception, e:
        print e
        #当没有进度时，返回 0
        return HttpResponse("0")
             
#返回实时结果集
def weakpass_json(request):
    try:
        return HttpResponse(json.dumps(weakpass_object.return_result),content_type="application/json")
    except:
        #当没有进度时，返回 0
        return HttpResponse("0")

