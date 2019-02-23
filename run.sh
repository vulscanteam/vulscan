#!/bin/bash
python manage.py clearsessions && python manage.py makemigrations && python manage.py migrate && (/sbin/ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:") &&  python manage.py runserver 0.0.0.0:8000
