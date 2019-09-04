import whois
import json
import subprocess
from django.http import HttpResponse

import json
import urllib.request
import time
import os
import requests

# client_c = "49.235.16"
# a = "mysql -h10.249.50.199 -P16764 -uroot -p'vXi3m^YM93' --default-character-set=utf8 -A -e" + " " + "\"select prov_name from dnspod_ip_location.Province_Code where prov_id=(select bProvince from dnspod_ip_location.Tbl_IP_Province_ISP where strIP = " + client_c + ".0" + ")\""
# print(a)
# client_ip = "49.235.16.147"

def unix_time(dt):
    # 转换成时间数组
    timeArray = time.strptime(dt, "%Y-%m-%d %H:%M:%S")
    # 转换成时间戳
    timestamp = int(time.mktime(timeArray))
    return timestamp

py_body = {"begtime":"2019-8-19 11:01:00","endtime":'2019-8-19 11:05:00',"attrid":50,"ip":"100.114.187.23"}
begtime = unix_time(py_body['begtime'])
endtime = unix_time(py_body['endtime'])
attrid = py_body['attrid']
target_ip = py_body['ip']
query_body = {"datatype": 0, "idtype": 1, "begtime": begtime, "endtime": endtime,
              "query": [{"qttrid": attrid, "ip": target_ip}]}
url = "http://9.94.61.166:28081/api/get_min_data_new"
data = json.dumps(query_body)
headers = {'Content-Type': 'application/json'}
response = requests.post(url,data)
print("response:",response)
print(begtime)