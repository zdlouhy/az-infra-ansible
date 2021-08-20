#!/usr/bin/env python3

DOCUMENTATION = '''
---
module: github_repo
short_description: Manage your repos on Github
'''

EXAMPLE = '''
kosik_certificate:
  hosts:
    - 'myhostname.p.mfit.systems'
    - 'myothername.p.mfit.systems'
  profile: 'kosik'
  state: present|absent
'''

from ansible.module_utils.basic import *
import os
import requests
import json

CFSSLHOST = "http://10.97.64.8:8888"

def api_request(method, request):
  """ Sends request to CFSSL API
  """
  data = request
  response = requests.post(CFSSLHOST+"/api/v1/cfssl/{}".format(method), json=data, timeout=10)

  if response.status_code != 200:
    raise Exception("API request error status={}".format(response.status_code))


  data = response.json()

  return data["result"]


def write_file(filename, content):
  """ Write content to file
  """
  f = open(filename, "w")
  f.write(content)
  f.close()

def certificate_present(data):
    default_crt_store = "/etc/ssl/certs"
    default_key_store = "/etc/ssl/private"

    certfile = default_crt_store+"/"+data['hosts'][0]+".crt"
    keyfile = default_key_store+"/"+data['hosts'][0]+".key"

    if os.path.isfile(certfile) == False:
       # Generate certificate request
       response_newkey = api_request("newkey",
         { "hosts": data['hosts'],
           "CN": data['hosts'][0],
           "key": {
             "algo": "rsa",
             "size": 2048
            }
         })
       csr = response_newkey["certificate_request"]
       key = response_newkey["private_key"]

       # Sign certificate request
       response_sign = api_request("sign", {"certificate_request": csr,"profile": data['profile']})
       crt = response_sign["certificate"]

       # Store certificate and key to disk
       write_file(keyfile, key)
       write_file(certfile, crt)
      
       msg = "certificate {} successfully created and signed".format(certfile) 

       return False, True, msg

    else:
       msg = "certificate {} located".format(certfile)       

       return False, False, msg

def certificate_absent(data):
    default_crt_store = "/etc/ssl/certs"
    default_key_store = "/etc/ssl/private"

    certfile = default_crt_store+"/"+data['hosts'][0]+".crt"
    keyfile = default_key_store+"/"+data['hosts'][0]+".key"

    if os.path.isfile(certfile) == True and os.path.isfile(keyfile) == True:
       os.remove(certfile)
       os.remove(keyfile)
       msg = "cert file {} and key file {} removed".format(certfile, keyfile)
    
       return False, True, msg

    else:
       msg = "cert file {} or key file {} missing"
       
       return True, False, msg

def main():

    fields = {
        "hosts": {"required": True, "type": "list"},
        "profile": {"required": True, "type": "str"},
        "state": {
            "default": "present",
            "choices": ['present', 'absent'],
            "type": 'str'
        }
    }

    choice_map = {
     "present": certificate_present,
     "absent": certificate_absent,
    }

    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = choice_map.get(
        module.params['state'])(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error creating cert", meta=result)


if __name__ == '__main__':
    main()
