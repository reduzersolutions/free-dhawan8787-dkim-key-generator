from __future__ import print_function
from pprint import pprint
import json
import time
from typing import Optional

import requests
import hashlib
import hmac
from urllib.parse import quote

from decouple import config

class LuxSciAPI:
    def __init__(self):
        self.secret_key = config("SECRET_KEY")
        self.token = config("TOKEN")
        self.hostname = config("HOSTNAME")
        self.accountID = config("ACCOUNT_ID")
        self.debug = config("DEBUG")
        self.user_agent = config("USER_AGENT")

    def auth_request(self):
        path = "/perl/api/v2/auth"
        method = 'POST'
        url = "https://" + self.hostname + path
        date = int(time.time())
        json_data = {
            'token': self.token,
            'date': date,
            'signature': hmac.new(
                self.secret_key.encode(),
                (self.token + "\n" + str(date) + "\n").encode(),
                hashlib.sha256
            ).hexdigest()
        }

        header_arr = {'content-type': 'application/json'}
        try:
            params = json.dumps(json_data)
        except Exception as e:
            return {'code': '400', 'info': {'success': 0, 'error': "Failure encoding JSON request: " + str(e)}}

        return self.call_api(url, params, header_arr, method, self.debug)

    def call_api(self, url, params, header_arr, method, debug):
        header_arr['User-Agent'] = self.user_agent
        if method == "GET":
            req = requests.get(url, data=params, headers=header_arr, timeout=30)
        elif method == "PUT":
            req = requests.put(url, data=params, headers=header_arr, timeout=30)
        else:
            req = requests.post(url, data=params, headers=header_arr, timeout=30)

        json.loads(req.text)
        code = req.status_code

        try:
            data = json.loads(req.text)
        except Exception as e:
            if debug:
                print("JSON Parse Exception: " + str(e) + "\n")
            return {'success': 0, 'error': "Non-JSON or unparsable data returned."}

        return {'code': code, 'data': data}

    def api_request(self, method: str, path: str, data: Optional[dict] = None):
        auth = self.auth_request()['data']['auth']
        qs = ""
        hmac_key = ""
        json_data = None

        if method == 'PUT' or method == 'POST':
            try:
                json_data = json.dumps(data)
                json_data.strip(" ")
                hmac_key = hashlib.sha256(json_data.encode()).hexdigest()
            except Exception as exception:
                if self.debug:
                    print("JSON Parse Exception: " + str(exception) + "\n")
                return {'code': 400, 'info': {'success': 0, 'error': "Failure encoding JSON request: " + str(exception)}}
        else:
            list_ar = list()
            if data:
                for key, value in data.items():
                    list_ar.append(quote(key, safe='') + "=" + quote(data[key], safe=''))
            qs = str.join('&', list_ar)

        url = "https://" + self.hostname + path + "" if qs == "" else "?" + qs

        # Send the POST/PUT body
        header_arr = {}
        if 'json_data' in locals():
            header_arr = {'content-type': 'application/json'}

        to_sign = auth + "\n" + method.upper() + "\n" + path + "\n" + qs + "\n" + hmac_key + "\n"

        sig = hmac.new(self.secret_key.encode(),
                       to_sign.encode(),
                       hashlib.sha256
                       ).hexdigest()

        if 'header_arr' in locals():
            header_arr["Cookie"] = "signature=" + auth + ":" + sig
        else:
            header_arr = {"Cookie": "signature=" + auth + ":" + sig}

        # import pdb;pdb.set_trace()
        return self.call_api(url, json_data, header_arr, method, self.debug)

    def create_dkim(self, domain):
        path = f"/perl/api/v2/account/{self.accountID}/dkim"
        try:

            dkim_create_response = self.api_request(method="POST", path=path, data={
                "domain": domain,
            })
            if dkim_create_response['code'] == 200:
                path = f"/perl/api/v2/account/{self.accountID}/dkim/{domain}"
                return self.api_request(method="GET", path=path)
            else:
                raise Exception(dkim_create_response)

        except Exception as e:
            raise Exception(e)


    def get_dkim_details(self, domain: str):
        path = f"/perl/api/v2/account/{self.accountID}/dkim/{domain}"
        return self.api_request(path=path, method="GET", data=None)


if __name__ == '__main__':
    api = LuxSciAPI()

    try:
        pprint(api.create_dkim("pittsburghtherapygroup.com"))
        # pprint(api.get_dkim_details("pittsburghtherapygroup.com"))
    except Exception as e:
        print("Exception when calling AuthenticationApi->authentication: %s\n" % e)
