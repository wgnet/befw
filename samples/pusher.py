#!/usr/bin/env python2.7
#
# Copyright 2018-2019 Wargaming Group Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import print_function
import time
import re
from sys import argv
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:
    import consul
except ImportError:
    raise SystemExit("Please install python-consul and try again!")



def genpath(level, service):
    level = int(level)
    if level == 1:
        path = "befw/{}/".format(service)
    elif level == 2:
        path = "befw/{}/{}/".format(dc, service)
    elif level == 3:
        path = "befw/{}/{}/{}/".format(dc, nn, service)
    else:
        path = "befw/{}/{}/{}/".format(dc, nn, service)
    return path


def service2name(name, meta):
    name = re.sub(pattern="[^\.-_a-zA-Z0-9]", repl="", string=name)
    proto = "udp" if "udp" in meta['Tags'] else "tcp"
    port = str(meta['Port'])
    return "{}_{}_{}".format(name, proto, port)


def services_list(*args):
    s = lc.agent.services()
    for x in s:
        print("* ", service2name(x, s[x]))
        print("    ", "Name", "=>", x)
        for k in s[x]:
            print("    ", k, "=>", s[x][k])


def services_add(*args):
    if len(args) < 3:
        return print("Usage: add <name> <proto(udp/tcp)> <port>")
    proto = "udp" if args[1] == "udp" else "tcp"
    x = lc.agent.service.register(
        name=args[0],
        tags=['befw', proto],
        port=int(args[2])
    )
    print("Service added: ", x)


def services_rm(*args):
    if len(args) < 1:
        return print("Usage: rm <name>")
    s = lc.agent.services()
    for x in s:
        n = service2name(x, s[x])
        if n == args[0]:
            lc.agent.service.deregister(s[x]['ID'])
            print("Service", n, "removed")
            c.kv.delete(key=genpath(3, n), recurse=True, dc=dc)
            print("KV for ", n, "removed")


def clients_list(*args):
    if len(args) < 1:
        return print("Usage: clist <service> [level(1/2/3)]")
    if len(args) == 2:
        level = [args[1]]
    else:
        level = [1, 2, 3]
    for v in level:
        path = genpath(v, args[0])
        idx, keys = c.kv.get(path, dc=dc, keys=True)
        if keys:
            print(path)
            print("\n".join([' *' + x.replace(path, "") for x in keys]))
    pass


def clients_add(*args):
    if len(args) < 3:
        return print("Usage: cadd <service> <ip> <level(1/2/3)> [expiry(1d by default)]")
    if len(args) == 4:
        if int(args[3]) < 0:
            expiry = -1*3601*24
        else:
            expiry = int(args[3]) + int(time.time())
    else:
        expiry = 3600 * 24 + int(time.time())
    path = genpath(args[2], args[0])
    path += args[1]
    c.kv.put(key=path, value=str(expiry), dc=dc)
    return print("Added {} to {} with expiry={}".format(args[1], path, expiry))
    pass


def clients_rm(*args):
    if len(args) < 2:
        return print("Usage: crm <service> <ip> [level(1/2/3)]")
    if len(args) == 3:
        level = [args[2]]
    else:
        level = [1, 2, 3]
    for v in level:
        path = genpath(v, args[0])
        path += args[1]
        print("Deleting", path)
        c.kv.delete(key=path, dc=dc)
    # show out


if __name__ == '__main__':
    # to work with KV
    from os.path import expanduser
    try:
        cfg = {}
        with open(expanduser("~/.pusher.conf")) as f:
            for l in f:
                ll = [x for x in l.strip().split("=")]
                cfg[ll[0].strip()] = "=".join(ll[1:])
    except Exception:
        raise SystemExit("Please edit ~/.pusher.conf to proceed")

    if "host" not in cfg:
        cfg["host"] = "localhost"
    if "port" not in cfg:
        cfg["port"] = 8500
    if "dc" not in cfg:
        cfg["dc"] = consul
    if "token" not in cfg:
        cfg["token"] = None
    if "verify" not in cfg:
        cfg["verify"] = False
    if "cert" not in cfg:
        cfg["cert"] = None


    c = consul.Consul(host=cfg["host"], port=cfg["port"], token=cfg["token"], dc=cfg["dc"], verify=cfg["verify"], cert=cfg["cert"])
    lc = consul.Consul(host=cfg["host"], port=cfg["port"], verify=cfg["verify"], cert=cfg["cert"])
    conf = lc.agent.self()
    nn = conf["Config"]["NodeName"]
    dc = conf["Config"]["Datacenter"]
    print("[+] DC=", dc, ", Node=", nn)
    if len(argv) == 1:
        print("Usage:", argv[0], "list|add|rm|clist|cadd|crm <opts>")
        exit(0)
    if argv[1] == "list":
        exit(services_list(*argv[2:]))
    elif argv[1] == "add":
        exit(services_add(*argv[2:]))
    elif argv[1] == "rm":
        exit(services_rm(*argv[2:]))
    elif argv[1] == "clist":
        exit(clients_list(*argv[2:]))
    elif argv[1] == "cadd":
        exit(clients_add(*argv[2:]))
    elif argv[1] == "crm":
        exit(clients_rm(*argv[2:]))
    else:
        print("Usage:", argv[0], "list|add|rm|clist|cadd|crm <opts>")
        exit(0)
