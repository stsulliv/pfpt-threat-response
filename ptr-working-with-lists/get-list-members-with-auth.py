#!/usr/bin/python

# basic script that uses Python requests to GET json result from REST API
# added header and API Key authentication

# import modules
import requests
import json

# required to avoid InsecureRequestWarning: Unverified HTTPS request is being made.
import urllib3

urllib3.disable_warnings()

r = requests.get('https://app.example.com/api/lists/5/members.json',
  headers={'Authorization': '111a1111-2223-333e-4ea4-55555555ee5e'}, verify=False)

json_object = json.dumps(r.json(), indent=4)

print(json_object)
