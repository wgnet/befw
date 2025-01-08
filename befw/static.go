/**
 * Copyright 2018-2023 Wargaming Group Limited
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

import (
	"fmt"
	"github.com/wgnet/befw/logging"
	"io/ioutil"
	"net"
	"path"
	"regexp"
	"strings"
)

const (
	REGEX_BEFW = "^befw/\\S+/(?:" + REGEXP_IP4_NET + "|" + REGEXP_IP6_NET + "|" + "\\$\\S+\\$)$"
)

var BEFWRegexp = regexp.MustCompile(REGEX_BEFW)

func filterStrings(filterFunc func(string) bool, array []string) []string {
	result := make([]string, 0)
	for _, elem := range array {
		if filterFunc(elem) {
			result = append(result, elem)
		}
	}
	return result
}

func splitLines(data []byte) []string {
	return filterStrings(func(x string) bool { return len(x) > 0 },
		regexp.MustCompile("\\s+").Split(string(data), -1))
}

func (this *config) getLocalIPSets() map[string][]string {
	result := make(map[string][]string)
	if files, e := ioutil.ReadDir(this.IPSetDir); e == nil {
		for _, file := range files {
			if !strings.HasSuffix(file.Name(), ".ipset") {
				continue
			}
			for _, set := range this.StaticSetList {
				if strings.HasPrefix(file.Name(), set.Name) {
					continue
				}
			}
			name := path.Join(this.IPSetDir, file.Name())
			if data, e := ioutil.ReadFile(name); e == nil {
				// create ipset
				v := ipset{name: file.Name(), ipList: make([]*net.IPNet, 0)}
				for _, ip := range splitLines(data) {
					_, cidr, e := net.ParseCIDR(strings.TrimSpace(ip))
					if e == nil {
						v.ipList = append(v.ipList, cidr)
					}
				}
				result[v.name] = nets2string(v.ipList)
			}
		}
	}
	return result
}

var ipNetRegexp *regexp.Regexp

func path2ipnet(path string) (r *net.IPNet) {
	if !BEFWRegexp.MatchString(path) {
		return nil
	} // not befwpath
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return nil
	}
	last := strings.Join(parts[len(parts)-2:], "/") // Try last two elements
	if _, cidr, e := net.ParseCIDR(last); e == nil && cidr != nil {
		return cidr
	}
	last = parts[len(parts)-1]
	if isIPv6(last) {
		last += "/128" // IPv6 address
	} else {
		last += "/32" // IPv4 addresss
	}
	if _, cidr, e := net.ParseCIDR(last); e == nil && cidr != nil {
		return cidr
	} // Try only last element
	return nil
}

func (this *config) getLocalServices() []bService {
	result := make([]bService, 0)
	uniqPorts := map[netProtocol][]bPort{
		PROTOCOL_TCP: make([]bPort, 10, 10),
		PROTOCOL_UDP: make([]bPort, 10, 10),
	}
	// 1. Scan directory
	if files, e := ioutil.ReadDir(this.ServicesDir); e == nil {
	serviceLoop:
		for _, file := range files {
			if !strings.HasSuffix(file.Name(), ".json") {
				continue serviceLoop
			}
			name := path.Join(this.ServicesDir, file.Name())
			if data, e := ioutil.ReadFile(name); e == nil {

				// 2. Parse service JSON
				srv, err := ServiceFromJson(data)
				if err != nil {
					logging.LogWarning("Bad service file", file.Name(), err)
					continue
				}
				logging.LogDebug("New service: ", srv.String())

				// 3. Check overlapping ports (warning only)
				for _, port := range srv.Ports {
					if _, ok := uniqPorts[port.Protocol]; !ok {
						continue
					}
					var uniq []bPort = uniqPorts[port.Protocol]
					for _, exist := range uniq {
						if exist.IsIntersect(&port) {
							// Only warning. Overlapping port reservation should not block service registration
							logging.LogWarning("Service ", srv.Name, " has overlapping port: ", port.toTag())
							// continue serviceLoop
						}
					}
					uniq = append(uniq, port)
				}

				// 4. Append service
				result = append(result, *srv)
			}
		}
	}
	return result
}

func nets2string(nets []*net.IPNet) []string {
	result := make([]string, len(nets))
	for i, k := range nets {
		ones, _ := k.Mask.Size()
		result[i] = fmt.Sprintf("%s/%d", k.IP.Mask(k.Mask).String(), ones)
	}
	return result
}
