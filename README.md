# BEFW project
###### Dynamic Host-Based Firewall
# Intro
**BEFW** is a couple of golang-written tools that are eligible to maintain dynamic firewall rules across the datacenter(s).
The approach is based on the service discovery concept: if we know there's a service, we can protect it. If we know there's a client for the service, we can allow him to connect to.
BEFW is using consul service catalog to store services ( with their tcp/udp ports ) and is using consul key-value storage to store services clients.
It's just a bit smarter than ```curl localhost:8200/v1/agent/services|perl -e '<script>'|iptables-restore```, but 'a bit' is significant here.
# Requirements
- Any modern Linux distro with iptables & ipset support.
- You must have at least one consul cluster with acl support enabled.
- You must have consul agent on every node that runs befw.
- We provide the only PuppetDB orchestration provider. You may need to develop yourth.

# How to build
It's old-style project, you don't need anything except golang>=1.9, automake & bash.
Just type make, you sould get something like that:
```
$ cd befw-0.0.9
$ make
make[1]: Entering directory `befw-0.0.9/src'
./build.sh
ok      _/builddir/build/BUILD/befw-0.0.9/src/befw      0.013s
ok      _/builddir/build/BUILD/befw-0.0.9/src/puppetdbsync      0.011s
make[1]: Leaving directory `befw-0.0.9/src'
```
***
# Deployment scheme
**BEFW** is not only tools but the approach too. If you build dynamic firewall from scratch, you may use our deployment guide.
## Consul cluster
1. [Install](https://www.consul.io/docs/install/index.html) regular consul cluster ( or federated cluster ) with N ( N % 2 == 1) servers and M agents. Each server must have consul agent running.
2. Push [some data](samples/post.sh) and enjoy
### ACLs
To protect your firewall configuration from unauthorized changes you need to create at least 3 acl sets on your consul cluster.
To enable ACL support please read this [article](https://www.consul.io/docs/guides/acl-legacy.html).
#### anonymous ACL
Allows anyone to read data from firewall ( usable for monitoring, metrics & UI for end users). [Example](samples/anonymous.acl).
#### node/agent ACL
Allows node/agent to read firewall configuration and register services. [Example](samples/node.acl).
#### Commit/Master ACL
Allows 3pc software to write firewall configuration and purge expired data. [Example](samples/master.acl).
## Configuration
We use single consul datacenter to store firewall KV and we call it *dc*. You should specify this datacenter into configuration file.
We use multiple consul datacenters ( one per site ) to store services & local KVs.
You may use single-dc configuration, specify it's name as *dc* though.
## Default firewall rules
3. Change default [**iptables template**](samples/iptables.rules)
## Service
4. Install & launch befw-firewalld service on every agent node
5. Edit [sample configuration](samples/befw.conf) and place it to /etc/befw.conf
6. Place [sample service](samples/service.json) to *services dir* and see what will happen
## Puppet/Hiera/PuppetDB
*We use puppet to do items 3-6 and below as we have a huge puppet installation. Skip this if you don't.*
Puppet provides a great way to enumerate services on every node. You can just add something like that in every role/application-definition class:
```puppet
file { "/etc/befw.service.d/${title}.json":
    ensure  => file,
    content => "<-- json here -->",
}
```
This will provide your services in consul automagically. Just a few patches once will save your time forever.
See [samples](samples/puppet/) for more information.
### befw-sync
Here, in Wargaming, we also use hiera & puppetdb to provide both services & clients for our services. The idea is that if we can collect & commit something to puppetdb ( like 'i_need_this_service_to_work'), that we can just grab it from puppetdb and store into consul.
**befw-sync** does this job, looking into puppetdb for a corresponding *resource* and grabbing parameters to push to consul KV storage.
See [sample config](samples/befw.sync.conf) to get into, but we doubt it is useful if you don't have such huge puppet installation on your world.
# Managing rules
## Adding new service
- Place a service file to *services* directory or
- Post a http request to local consul agent ( v1/agent/register ) or
- Allow consul-supported software ( like vault ) to manage it on its own

**N.B.** use tag 'befw' to generate rules for this service. Use tags 'port/protocol' ( like '80/tcp' ) to specify *additional* ports for the service.
## Adding new rules
- Place ip/network and expiry value to KV storage on *dc* datacenter or
- Place alias and expiry value to KV storage on *dc* datacenter or
- Place a new data to alias definition to KV storage on *dc* datacenter

**N.B.** You can specify world, dc or node level while placing the rules.
### Examples
```go
consul.KV().Put("befw/service_tcp_443/192.168.1.1/30", time.now()+2*week)
consul.KV().Put("befw/dc/service_tcp_443/192.168.1.1/30", time.now()+2*week)
consul.KV().Put("befw/dc/nodename/service_tcp_443/192.168.1.1/30", time.now()+2*week)
consul.KV().Put("befw/service_tcp_443/$trusted$", -1) # <0 never expires
consul.KV().Put("befw/$alias$/$trusted$/192.168.1.1.30", time.now()+1*hour)
```
## Tools
[**pusher**](samples/pusher.py) is a very primitive python (2.7) tool to manage befw manually. Please avoid using it in production.
**Usage**: ./pusher.py list|add|rm|clist|cadd|crm  [opts]
**Config file**: ~/.pusher.conf
```bash
host=localhost
port=8500
dc=consul
token=2375a28a-75ec-4b5f-a30f-3e68f8239a0a
```
**Example usage**:
```bash
# no clients for service
$ ./pusher.py clist myown_tcp_5672
[+] DC= dc , Node= node
# adding new one for level 3 ( node )
$ ./pusher.py cadd myown_tcp_5672 127.0.0.1 3
[+] DC= dc , Node= node
Added 127.0.0.1 to befw/dc/node/myown_tcp_5672/127.0.0.1 with expiry=1554896188
# yes we have it on KV now
$ ./pusher.py clist myown_tcp_5672
[+] DC= dc , Node= node
befw/dc/node/myown_tcp_5672/
 *127.0.0.1
# deleteting 127.0.0.1 from all levels
$ ./pusher.py crm myown_tcp_5672 127.0.0.1
[+] DC= dc , Node= node
Deleting befw/myown_tcp_5672/127.0.0.1
Deleting befw/dc/myown_tcp_5672/127.0.0.1
Deleting befw/dc/node/myown_tcp_5672/127.0.0.1
# no clients found
$ ./pusher.py clist myown_tcp_5672
[+] DC= dc , Node= node
$ 
```
# Changelog
See [CHANGELOG](CHANGELOG.md).
# Known issues
See [ISSUES](ISSUES.md).
# Contributing
See [CONTRIB](CONTRIB.md).
