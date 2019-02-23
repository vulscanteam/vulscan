#coding=utf-8

#导入公共函数库
from function import *
# Create your views here.
import sys
reload(sys)
sys.setdefaultencoding("utf-8")

def index(request):
    return render(request,'plug.html')