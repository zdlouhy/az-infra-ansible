#!/usr/bin/env python3

DOCUMENTATION = '''
---
module: github_repo
short_description: Manage your repos on Github
'''

EXAMPLES = '''
- name: Create a github Repo
  github_repo:
    github_auth_key: "..."
    name: "Hello-World"
    description: "This is your first repository"
    private: yes
    has_issues: no
    has_wiki: no
    has_downloads: no
  register: result
- name: Delete that repo 
  github_repo:
    github_auth_key: "..."
    name: "Hello-World"
    state: absent
  register: result
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
         { "hosts": data.hosts,
           "CN": data.hosts[0],
           "key": {
             "algo": "rsa",
             "size": 2048
            }
         })
       csr = response_newkey["certificate_request"]
       key = response_newkey["private_key"]

       # Sign certificate request
       response_sign = api_request("sign", {"certificate_request": csr,"profile": CFSSLPROFILE})
       crt = response_sign["certificate"]

       # Store certificate and key to disk
       write_file(keyfile, key)
       write_file(certfile, crt)

    else:
      pass



def main():

    fields = {
        "hosts": {"required": True, "type": "list"},
        "profile": {"required": True, "type": "string"},
        "state": {
            "default": "present",
            "choices": ['present', 'absent'],
            "type": 'str'
        },
    }

    choice_map = {
     "present": certificate_present,
   #  "absent": github_repo_absent,
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
