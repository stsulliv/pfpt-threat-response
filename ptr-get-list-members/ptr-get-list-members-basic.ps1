#!/usr/bin/python

# basic script that uses Python requests to GET json result from REST API

# import modules
# we need the 'requests' module to access the REST API and 'json' to format the response.
import requests
import json

# After running you will notice an error similar to ...
# InsecureRequestWarning: Unverified HTTPS request is being made.
# uncomment the two lines below to resolve.  I recommend including in al future scripts.

# import urllib3
# urllib3.disable_warnings()

r = requests.get('https://app.sample.com/api/lists/5/members.json', verify=False)

json_object = json.dumps(r.json(), indent=4)

print(json_object)
