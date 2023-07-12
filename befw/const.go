/**
 * Copyright 2018-2021 Wargaming Group Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
**/
package befw

const (
	staticIpsetPath    string = "/etc/befw.ipset.d"
	staticServicesPath string = "/etc/befw.service.d"
	staticRulesPath    string = "/etc/befw.rules.json"
	aclDatacenter             = "consul"
	iptablesStaticSet         = `-I BEFW {PRIORITY} -m set --match-set {NAME} src -j {TARGET}
`
	iptablesRulesLineMulti = `
# {NAME}
-A BEFW -p {PROTO} -m multiport --dports {PORTS} -m set --set {NAME} src -j ACCEPT
-A BEFW -p {PROTO} -m multiport --dports {PORTS} -j DROP
# /{NAME}
`
    iptablesRulesLine = `
# {NAME}
-A BEFW -p {PROTO} --dport {PORT} -m set --match-set {NAME} src -j ACCEPT
-A BEFW -p {PROTO} --dport {PORT} -j NFLOG --nflog-group 402
# /{NAME}
`
	iptablesNidsLine = `
-A BEFW -p tcp -m multiport --dports {NIDSPORTS} -j NFLOG --nflog-group 402
`

	iptablesRulesFooter = `
COMMIT
# /BEFW IPTABLES RULES @ {DATE}
`
	iptablesRulesHeader = `
# BEFW IPTABLES RULES @ {DATE}
*filter
:BEFW - [0:0]
-F BEFW
`
	packageName   = "befw-firewalld"
	consulAddress = "127.0.0.1:8500"

	SET_ALLOW = "rules_allow"
	SET_DENY = "rules_deny"
    V6  = "_v6"
	confSetPrefix  = "set."
)

var mandatoryIPSet = []string{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"} // "shoot yourself in the foot"-protection
var staticIPSetList = []staticIPSetConf{
	{
		Name:     SET_ALLOW,
		Priority: 1,
		Target:   "ACCEPT",
	},
	{
		Name:     SET_DENY,
		Priority: 2,
		Target:   "REJECT",
	},
}

const (
	ipprotoTcp befwServiceProto = "tcp"
	ipprotoUdp befwServiceProto = "udp"
)

const befwNFQueue = 402 // ord(befw)
const befwState = "/var/run/befw"
const befwStateSocket = "/var/run/befw/api.sock"

const befwStateBin = "/var/run/befw/state.bin"
const befwNillService = "anyother.service"

// Code behavior constants
const (
    ENABLE_BIN_CALLS        = false     // Allow to execute external commands in tests (such as 'echo')
    ENABLE_IPT_MULTIPORT    = false     // If true - fill templates based on --dports (allows multiple ports per one rule)
)
