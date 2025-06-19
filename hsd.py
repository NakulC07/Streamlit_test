import os
import requests
import urllib3
import http.client
import traceback
import pandas as pd
from requests_kerberos import HTTPKerberosAuth
from datetime import datetime
import json

requests.packages.urllib3.disable_warnings()

class HsdConnector:
    def __init__(self, kerberos_user=None):
        self.kerberos_user = kerberos_user

    def _get_response(self, req, headers):
        # Optionally log or use self.kerberos_user for auditing or custom headers
        response = requests.get(req, auth=HTTPKerberosAuth(), verify=False, headers=headers)
        if response.ok:
            try:
                response_data = response.json()
                return response_data
            except Exception as e:
                raise e
        else:
            response.raise_for_status()

    def get_hsd(self, hsd_id, fields=None):
        if fields == "":
            fields = None
        assert fields is None or (len(fields) > 0 and not isinstance(fields, str) and all([isinstance(f, str) for f in fields])), \
            "fields must be None or a list\iterator of strings. Got %s." % (repr(fields),)
        retry = 10
        while retry > 0:
            try:
                req = f"https://hsdes-api.intel.com/rest/article/{hsd_id}"
                if fields is not None:
                    req += "?fields=" + "%2C%20".join(fields)
                headers = {'Content-type': 'application/json'}
                # Optionally add kerberos_user to headers for tracking
                if self.kerberos_user:
                    headers['X-Kerberos-User'] = self.kerberos_user
                response_data = self._get_response(req, headers)
                if "data" in response_data:
                    return response_data["data"][0]
                else:
                    raise Exception('Could not find "data" in response...')
            except (urllib3.exceptions.MaxRetryError, requests.exceptions.ProxyError, http.client.RemoteDisconnected):
                retry -= 1
            except Exception as e:
                retry -= 1

    def get_user_private_queries(self, user_idsid=None):
        url = "https://hsdes-api.intel.com/rest/query/MetaData"
        headers = {'Content-type': 'application/json'}
        if user_idsid is None:
            user_idsid = self.kerberos_user
        params = {
            "owner": user_idsid,  # Filter by the owner's idsid
            "category": "private"
        }
        try:
            response = requests.get(url, auth=HTTPKerberosAuth(), verify=False, headers=headers, params=params)
            if response.ok:
                response_data = response.json()
                if "data" in response_data:
                    return response_data["data"]
                else:
                    raise Exception('Could not find "data" in response...')
        except Exception as e:
            raise e

if __name__ == "__main__":
    connector  = HsdConnector()
    queries = connector.get_user_private_queries()
    print(queries)