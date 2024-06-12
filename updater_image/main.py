#!/usr/bin/env python3

from kubernetes import client, config
from os import environ
from os.path import exists, expanduser
import sys
import json
import subprocess
import requests
import time
import datetime


def find_creds():
    # creds = {}
    try:
        if all(x in environ for x in ['api_compute', 'pc_username', 'pc_password']):
            creds = {'api_compute': environ.get('api_compute'), 'username': environ.get('pc_username'), 'password': environ.get('pc_password')}
        elif exists("./credentials.json"):
            creds = json.load(open('./credentials.json'))
        elif exists("/credentials.json"):
            creds = json.load(open('/credentials.json'))
        else:
            creds = json.load(open(f"{expanduser('~')}/.prismacloud/credentials.json"))
    except:
        dprint("Couldn't find a set of credentials.\nIt should be in variables or one of\n~/.prismacloud/credentials.json\n./credentials.json")
        return None
    return creds


def authenticate():
    # This first condition will help us not hit the authentication API for every iteration.
    global tokenBirthtime
    if (all(x in globals() for x in ['token', 'url'])) and (time.time() - tokenBirthtime < 3600):
        # print(f'Skipped Auth! {time.time() - tokenBirthtime} seconds passed.')
        return token, url
    else:

        # Tries to authenticate until success
        succeed = False
        while not succeed:
            try:
                creds = find_creds()
                rbody = {'username': creds['username'], 'password': creds['password']}
                r = requests.post(f"{creds['api_compute']}/api/v1/authenticate", json = rbody)
                if r.status_code == 200:
                    succeed = True
                    # print("New Auth")
                    tokenBirthtime = time.time()
                    response = r.json() 
                    return response['token'], creds['api_compute']
                else:
                    dprint(f'Auth did not succeed(status code {r.status_code}), waiting 5 min')
                    raise ValueError(f'Auth did not succeed(status code {r.status_code}), waiting 5 min')
            except:
                if creds is None:
                    return None, None
                else:
                    dprint("Couldn't auth for some reason, sleeping for 5 min")
                time.sleep(300)
                continue


def gen_yaml(token, url, defender_options):
    defender_options["consoleAddr"] == url.split("/")[2]
    dprint(f"Discovered console Addr as {defender_options['consoleAddr']}")
    succeed = False
    while not succeed:
        try:
            headers = {"Authorization": f"Bearer {token}"}
            body = json.dumps(defender_options)
            r = requests.post(f"{url}/api/v1/defenders/daemonset.yaml", headers=headers, data=body)
            if r.status_code == 200:
                data = r.text
                # ds_yaml = open("./defender_ds.yaml", "w")
                # ds_yaml.write(data)
                succeed = True
                return data
                # return succeed
                # No return data need since the yaml is writen to disk
            else:
                dprint(r.text)
                dprint(f"The error did not succeed.  Code {r.status_code}")
                raise ValueError('The API call did not succeed')
        except:
            dprint("Data Call Didn't work")
            time.sleep(300)
            continue

 
def get_ver(token, url):
    succeed = False
    while not succeed:
        try:
            headers = {"Authorization": f"Bearer {token}"}
            r = requests.get(f"{url}/api/v1/version", headers=headers)
            if r.status_code == 200:
                data = r.json()
                succeed = True
                return data
            else:
                print(f"The error did not succeed.  Code {r.status_code}")
                raise ValueError('The API call did not succeed')
        except:
            dprint("Data Call Didn't work")
            time.sleep(300)
            continue


def k8s_interact(task, defender_ds_yaml={}):
    # config.load_kube_config()
    config.load_incluster_config()
    appv1 = client.AppsV1Api()
    options = {}
    if exists("/run/secrets/kubernetes.io/serviceaccount/namespace"):
        f = open("/run/secrets/kubernetes.io/serviceaccount/namespace", "r")
        options["namespace"] = f.read()
    else:
        options["namespace"] = "twistlock"

    defender_ds = appv1.read_namespaced_daemon_set(namespace=options["namespace"], name="twistlock-defender-ds", _preload_content=False)
    defender_dict = json.loads(defender_ds.data)

    if task == "ver":
        return k8s_ver(defender_dict)
    elif task == "build_opts":
        return build_opts(defender_dict, options)
    elif task == "deploy":
        subprocess.run(["kubectl", "apply", "-f", "-"], input=defender_ds_yaml, encoding='utf-8')


def k8s_ver(defender_dict):
    # Needed to parse out the image name to determine the dotted version number
    defender_img = defender_dict["spec"]["template"]["spec"]["containers"][0]["image"]
    defender_tag = defender_img.split(":")[1].split("_") 
    defender_ver = f"{defender_tag[1]}.{defender_tag[2]}.{defender_tag[3]}"

    return defender_ver

def build_opts(defender_dict, options):
    defender_vars = defender_dict["spec"]["template"]["spec"]["containers"][0]["env"]
    defender_limits = defender_dict["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]
    for x in defender_vars:
        if x['name'] == "DEFENDER_TYPE":
            if x['value'] == "cri":
                for y in defender_dict["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]:
                    if y["name"] == "cri-data" and y["mountPath"] == "/var/lib/containerd":
                        options["containerRuntime"] = "containerd"
                    elif y["name"] == "cri-data" and y["mountPath"] == "/var/lib/containers":
                        options["containerRuntime"] = "crio"
            elif x['value'] == "daemonset":
                options["containerRuntime"] = "docker"
        if x['name'] == "CLOUD_HOSTNAME_ENABLED" and 'value' in x:
            options["uniqueHostname"] = eval(x['value'].capitalize())
        if x['name'] == "MONITOR_SERVICE_ACCOUNTS" and 'value' in x:
            options["serviceaccounts"] = eval(x['value'].capitalize())
        if x['name'] == "COLLECT_POD_LABELS" and 'value' in x:
            options["collectPodLabels"] = eval(x['value'].capitalize())
        if x['name'] == "MONITOR_ISTIO" and 'value' in x:
            options["istio"] = eval(x['value'].capitalize())
        if x['name'] == "DEFENDER_CLUSTER" and 'value' in x:
            options["cluster"] = x['value']
        if "seLinuxOptions" in defender_dict["spec"]["template"]["spec"]["containers"][0]["securityContext"]: 
            if defender_dict["spec"]["template"]["spec"]["containers"][0]["securityContext"]["seLinuxOptions"]["type"] == "spc_t":
                options["selinux"] = True
    try:
        options["memoryLimit"] = int(defender_limits['memory'].rstrip("Mi"))
    except:
       try:
           options["memoryLimit"] = int(defender_limits['memory'].rstrip("Gi"))
       except:
           pass 

    options["cpuLimit"] = int(defender_limits['cpu'].rstrip("m"))
    options["privileged"] = defender_dict["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"]
    options["orchestration"] = "Kubernetes"

    if exists("./defender_options.json"):
        defender_opts = json.load(open('./defender_options.json'))
        # Combine / Update options with the static requirements in file
        options.update(defender_opts)
    elif exists(f"{expanduser('~')}/.prismacloud/defender_options.json"):
        defender_opts = json.load(open(f"{expanduser('~')}/.prismacloud/defender_options.json"))
        options.update(defender_opts)
    else:  
        dprint("Defender Options not found")
    return options
    

def version_match(token, url):
    latest_ver = get_ver(token, url)
    current_ver = k8s_interact("ver")
    if latest_ver == current_ver:
        return True
    else:
        return False


def dprint(msg):
    print(f"{datetime.datetime.now().astimezone().strftime('%Y-%m-%dT%H:%M:%S %Z')} -- {msg}")

def main():
    global token,url
    token, url = authenticate()
    if token is None:
        sys.exit(f"{datetime.datetime.now()} -- No credentials found. Exiting program.")  # Stop program execution

    if version_match(token, url):
        dprint("Up-to-Date!")
    else:
        dprint("Upgrade Available!")
        defender_opts = k8s_interact("build_opts")
        defender_ds_yaml = gen_yaml(token, url, defender_opts)
        k8s_interact("deploy", defender_ds_yaml)

if __name__ == '__main__':
    while "runonce" not in environ:
        main()
        dprint("Sleeping for a day")
        time.sleep(86400)
    else:
        main()
        dprint("Ran Once!")


    

