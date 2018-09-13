import hashlib
import json
import os
import requests
import sys

# What happens at the end
def wait_for_input(msg, error):
  if (msg != None and len(msg) > 0):
    print(msg)
  input("Press the any key man.")
  if (error):
    os._exit(420)

# Quit if there aren't enough params
if (len(sys.argv) <= 1):
  wait_for_input("You must supply a valid file to be scanned. Note that this will not submit the actual file, only the file's hash.", True)
if not os.path.isfile(sys.argv[1]):
  wait_for_input("That file doesn't exist.", True)

# Add default headers
headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"
}

# Open the sample file and compute a sha1 hash for it
sha1_hash_builder = hashlib.sha1()
try:
  with open(sys.argv[1], 'rb') as handle:
    while(True):
      chunk = handle.read(8192)
      if chunk:
        sha1_hash_builder.update(chunk)
      else:
        break
except Exception as e:
  wait_for_input("Could not open sample file: %s" % str(e), True)

# Build params to send to virus total REST api
try:
  params = {
    'apikey': '<Virus Total API Key',
    'resource': sha1_hash_builder.hexdigest()
  }
except Exception as e:
  wait_for_input("Could not compute a sha1 hash for that file: %s" % str(e), True)

# Make the actual request to the virustotal api
try:
  response = requests.post(
    'https://www.virustotal.com/vtapi/v2/file/report',
    params = params
  )
except Exception as e:
  wait_for_input("Could not connect to VirusTotal REST API: %s" % str(e), True)

# Try and decode the response from the server and print it
try:
  json_response = response.json()
  print(json.dumps(json_response, sort_keys=True, indent=2))
  if (json_response['positives'] and json_response['total']):
      print("Malware Positives: %s / %s " % (json_response['positives'], json_response['total']))
except Exception as e:
  wait_for_input("Could not parse and print the JSON response from the VirusTotal REST API: %s" % str(e), True)

wait_for_input(None, False)
