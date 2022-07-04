import requests
import json
import time
import urllib.request
import urllib
import os
from flask import Flask, Response, request

app = Flask(__name__)

URLSCANIO_API_KEY = os.getenv('URLSCANIO_API_KEY')
SLEEP_TIME = os.getenv('SLEEP_TIME')
RETRY = os.getenv('RETRY')

@app.route('/')
def hello():

    url = request.args["url"]

    if (url == ""):
        return Response(json.dumps('{success: false, "message": "Hatalı URL"}'))

    headers = {'API-Key': URLSCANIO_API_KEY, 'Content-Type': 'application/json'}
    data = {"url": url, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
    
    for x in range(RETRY):
        time.sleep(10)

        data = json.dumps(response.json()['api'])
        api_url = data[1:-1]

        json_data = urllib.request.urlopen(api_url)
        db = json.loads(json_data.read())

        return Response(json.dumps('{success: true, "data": '+db+'}'), mimetype='application/json')

    return Response(json.dumps('{success: false, "message": "Server Zaman Aşımına Uğradı"}'))

def parseJSON(db):
    screenshotURL = db.get('task').get('screenshotURL')  
    file_name = screenshotURL.split("/")[-1]

    submitter_country = db.get('submitter').get('country')

    overall_verdicts = db.get('verdicts').get('overall').get('score')           
    overall_malicious = db.get('verdicts').get('overall').get('malicious')
    overall_hasverdicts = db.get('verdicts').get('overall').get('hasVerdicts')
    verdict_categories = db.get('verdicts').get('overall').get('categories')
    verdict_brands = db.get('verdicts').get('overall').get('brands')
    verdict_tags = db.get('verdicts').get('overall').get('tags')                            
    if overall_hasverdicts == True:
        potentially_malicious = overall_malicious
    else:
        potentially_malicious = "UNDETECTED"                                     

    page_ip = db.get('page').get('ip')
    page_domain = db.get('page').get('domain')
    page_country = db.get('page').get('country')
    page_city = db.get('page').get('city')

    report_URL = db.get('task').get('reportURL')

    geo_ip_datas = {}                                                                        
    geo_data_list = db.get('meta').get('processors').get('geoip').get('data')
    for n in geo_data_list:
        ip = n.get('ip')
        if ip == page_ip:
            geoip_data = n.get('geoip')
                                                                  

    rdns_data= db.get('meta').get('processors').get('rdns').get('data')

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

    return final_json_data
