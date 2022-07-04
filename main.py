import requests
import json
import time
import urllib.request
import urllib
import os
from decouple import config
from requests.adapters import HTTPAdapter, Retry

URL_TO_BE_SCANNED= config('URL_TO_BE_SCANNED')
URLSCAN_TOKEN = config('URLSCAN_TOKEN')
TIME_ENV= config('TIME_ENV', default=10, cast=int)


headers = {'API-Key': URLSCAN_TOKEN, 'Content-Type': 'application/json'}
data = {"url": URL_TO_BE_SCANNED, "visibility": "public"}
response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
time.sleep(TIME_ENV)


data = json.dumps(response.json()['api'])
api_url = data[1:-1]

json_data = urllib.request.urlopen(api_url)
db = json.loads(json_data.read())

#xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

screenshotURL = db.get('task').get('screenshotURL')  #-----------------------
file_name = screenshotURL.split("/")[-1]


def download_image(url, filename):                   #SCREENSHOT
    #full_path = filepath + filename + '.jpg'
    urllib.request.urlretrieve(url, filename)


#download_image(screenshotURL, file_name)              #--------------------------

submitter_country = db.get('submitter').get('country')

overall_verdicts = db.get('verdicts').get('overall').get('score')           #--------------------------------------------------
overall_malicious = db.get('verdicts').get('overall').get('malicious')
overall_hasverdicts = db.get('verdicts').get('overall').get('hasVerdicts')
verdict_categories = db.get('verdicts').get('overall').get('categories')
verdict_brands = db.get('verdicts').get('overall').get('brands')
verdict_tags = db.get('verdicts').get('overall').get('tags')                            #VERDICTS
if overall_hasverdicts == True:
    potentially_malicious = overall_malicious
else:
    potentially_malicious = "UNDETECTED"                                     #----------------------------------------------------

page_ip = db.get('page').get('ip')
page_domain = db.get('page').get('domain')
page_country = db.get('page').get('country')
page_city = db.get('page').get('city')

report_URL = db.get('task').get('reportURL')

geo_ip_datas = {}                                                                        #---------------------------------------------------
geo_data_list = db.get('meta').get('processors').get('geoip').get('data')
for n in geo_data_list:
    ip = n.get('ip')
    if ip == page_ip:
        geoip_data = n.get('geoip')


#    country_name = n.get('geoip').get('country_name')                                               #GEOIP DATA LIST
#    time_zone = n.get('geoip').get('timezone')
#    city_name = n.get('geoip').get('city')

#    geo_ip_datas[ip] = str("[Country Name: " + country_name + "] [Timezone: " + time_zone + "] [City: " + city_name + "]")
                                                                                        #-------------------------------------------------------

rdns_data= db.get('meta').get('processors').get('rdns').get('data')

#print("screenshotURL= " + screenshotURL)
#print("reportURL= " + report_URL)
#print("ip= " + page_ip)
#print("Potentially Malicious= " + str(potentially_malicious))
#print(db.get('verdicts').get('overall'))
#print(db.get('verdicts').get('urlscan'))
#print(geoip_data)
#print(rdns_data)

final_json_data = {}
final_json_data ={
    "data":{
        "ScreenShotURL": screenshotURL,
        "ReportURL": report_URL,
        "IP": page_ip,
        "Potentially_Malicious": potentially_malicious,
        "Overall_Verdicts": db.get('verdicts').get('overall'),
        "URLScan_Verdicts": db.get('verdicts').get('urlscan'),
     "GeoIP_Data": geoip_data,
        "RDNS_Data": rdns_data,
    }
}
print(json.dumps(final_json_data))


#requests.post("http://localhost", verify=False)


with open('testdata.json', 'w', encoding='utf-8') as f:
    json.dump(final_json_data, f, ensure_ascii=False, indent=4)

os.system("json-server --watch testdata.json --port 8000")