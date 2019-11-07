# BEFW DEMO
## What is this for
This demo explains how befw stack works with some *real* data. It may help you to start using befw or teach you how it works from your first hand experience.
## What you will get
A built-from-scratch model with one service, 3 clients, puppet <-> befw integration and so on.
## How to procees
To proceed just take eight easy steps:
1. Build befw-firewalld and befw-sync
2. Install [consul](http://consul.io) on your Linux PC
3. Run `sudo iptables-restore < iptables.rules`
4. Run `consul agent -dev -datacenter=eu`
5. Run `sudo befw-firewalld -debug -config befw.conf` in separate console
6. Run `sh register.sh` and see how befw will proceed with ssh service
7. Run `sh puppetdb.sh` to create a fake puppetdb http server
8. Run `befw-sync -debug -config befw.sync.conf` and see how befw-sync will put data from puppetdb to consul and how befw will fire a trigger and alter its rules

## How to check result is valid
On step 5 you'll get rules from rules.json
On step 6 you'll get a rule about ssh ( port 22/tcp ) service
On step 8 you'll get a ssh_tcp_22 ipset fullfilled with 3 *client* networks

