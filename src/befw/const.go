/**
 * Copyright 2018-2019 Wargaming Group Limited
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
	iptablesRulesLine         = `
# {NAME}
-A BEFW -p {PROTO} --dport {PORT} -m set --set {NAME} src -j ACCEPT
-A BEFW -p {PROTO} --dport {PORT} -j DROP
# /{NAME}
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
)

var staticIPSetList = []staticIPSetConf{
	{
		Name:     "rules_allow",
		Priority: 1,
		Target:   "ACCEPT",
	},
	{
		Name:     "rules_deny",
		Priority: 2,
		Target:   "REJECT",
	},
}

const (
	ipprotoTcp befwServiceProto = "tcp"
	ipprotoUdp befwServiceProto = "udp"
)

const (
	DebugConfiguration = iota
	ProductionConfiguration
)

const befwNFQueue = 402 // ord(befw)
const befwState = "/var/run/befw"
const befwStateSocket = "/var/run/befw/api.sock"

const befwStateBin = "/var/run/befw/state.bin"
const befwNillService = "anyother.service"

var ConfigurationRunning int = ProductionConfiguration
