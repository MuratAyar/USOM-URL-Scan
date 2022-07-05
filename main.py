import json
import os
import requests
import time
import urllib
import urllib.request
from flask import Flask, Response, request

app = Flask(__name__)

URLSCANIO_API_KEY = os.getenv('URLSCANIO_API_KEY')
SLEEP_TIME = os.getenv('SLEEP_TIME', default=3)
RETRY = os.getenv('RETRY', default=5)
print(URLSCANIO_API_KEY)

@app.route('/')
def hello():
    if 'url' not in request.args:
        return get_error_response("url parametresi verilmedi")

    url = request.args["url"]


    headers = {'API-Key': URLSCANIO_API_KEY, 'Content-Type': 'application/json'}
    data = {"url": url, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data)).json()

    if 'api' not in response:
        return get_error_response(response['message'])

    data = json.dumps(response['api'])
    api_url = data[1:-1]

    for x in range(RETRY):
        time.sleep(SLEEP_TIME)

        try:
            json_data = urllib.request.urlopen(api_url)
            db = json.loads(json_data.read())

            return get_succes_response(db)
        except:
            pass

    return get_error_response("Server Zaman Aşımına Uğradı")

def get_error_response(msg):
    return Response('{"success": false, "message": "' + msg + '"}', mimetype='application/json')


def get_succes_response(data):
    return Response('{"success": true, "data": ' + json.dumps(data) + '}', mimetype='application/json')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
