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

import(
	"testing"
    "fmt"
    "strings"
)

func TestUnmarshalJson(t *testing.T) {
	jsnService := `{"name":"example", "protocol":"tcp", "port":12345, "ports":[{"port":"1:42", "protocol":"udp"}]}`
    srv, err := ServiceFromJson([]byte(jsnService))
    if err != nil { t.Fail() }

    if srv.Name != "example" { t.Error("Wrong name", srv.Name) }
    score := 0
    for _, p := range srv.Ports {
        if p.toTag() == "12345/tcp" { score += 1 }
        if p.toTag() == "1:42/udp" { score += 1 }
    }
    if score != 2 { t.Error("Wrong ports", srv.Ports) }
}

func TestUnmarshalJsonLegacy(t *testing.T) {
	// Basic json
	jsnService := "{\"name\":\"example\", \"protocol\":\"tcp\", \"port\":12345}"
	service, err := LegacyServiceFromJson([]byte(jsnService))
	if err != nil { t.Errorf("Failed to unmarshal: %s", err);return }
	if service.ServiceName != "example" { t.Errorf("Bad name: %s != %s", service.ServiceName, "example") }
	if service.ServicePort != 12345 { t.Errorf("Bad port") }
	if service.ServiceProtocol != "tcp" { t.Errorf("Bad protocol") }

	// With ports and range
	jsnService = `{"name":"example", "protocol":"tcp", "port":12345, "ports":[{"port":"1:42", "protocol":"udp"}]}`
	service, err = LegacyServiceFromJson([]byte(jsnService))
	if err != nil { t.Errorf("Failed to unmarshal: %s", err);return }
	if service.ServiceName != "example" { t.Errorf("Bad name: %s != %s", service.ServiceName, "example") }
	if service.ServicePort != 12345 { t.Errorf("Bad port") }
	if service.ServiceProtocol != "tcp" { t.Errorf("Bad protocol") }
	if len(service.ServicePorts) != 1 && string(service.ServicePorts[0].Port) != "1:42" { t.Errorf("Bad ports unmarshalling") }

	// Default port, protocol from ports
	jsnService = `{"name":"example", "ports":[{"port":"11:42", "protocol":"udp"}]}`
	service, err = LegacyServiceFromJson([]byte(jsnService))
	if err != nil { t.Errorf("Failed to unmarshal: %s", err); return }
	if service.ServiceName != "example" { t.Errorf("Bad name: %s != %s", service.ServiceName, "example") }
	if service.ServicePort != 11 { t.Errorf("Bad port") }
	if service.ServiceProtocol != "udp" { t.Errorf("Bad protocol") }

	// Default port, protocol from ports
	jsnService = `{"name":"example", "ports":[{"port": 33, "protocol":"udp"}]}`
	service, err = LegacyServiceFromJson([]byte(jsnService))
	if err != nil { t.Errorf("Failed to unmarshal: %s", err); return }
	if service.ServiceName != "example" { t.Errorf("Bad name: %s != %s", service.ServiceName, "example") }
	if service.ServicePort != 33 { t.Errorf("Bad port") }
	if service.ServiceProtocol != "udp" { t.Errorf("Bad protocol") }

	// No ports, No port - wrong
	jsnService = `{"name":"example", "ports":[]}`
	service, err = LegacyServiceFromJson([]byte(jsnService))
	if err == nil || service != nil { t.Errorf("Expected FAIL on unmarshalling bad JSON") }

	// BAD! with bad port/range
	jsnService = `{"name":"example", "protocol":"tcp", "port":12345, "ports":[{"port":"65566", "protocol":"udp"}]}`
	service, err = LegacyServiceFromJson([]byte(jsnService))
	if err == nil { t.Errorf("Expected error for : %s", jsnService);return }

}

// Check support of tagPort in JSON
func TestUnmarshalJsonLegacy2(t *testing.T) {
    expectPorts := []string{"1", "2:3", "4:5/udp", "11:22/tcp"}
    jsnService := `{"name": "example", "ports": ["1", "2:3", "4:5/udp", {"port":"11:22"}]}`
	service, err := LegacyServiceFromJson([]byte(jsnService))
	if err != nil { t.Errorf("Failed to unmarshal: %s", err); return }
    for _, port := range expectPorts {
        bp, err := NewBPort(port)
        if err != nil { t.Fail() }
        var ok bool = false
        for _, realPort := range service.ServicePorts {
            if string(realPort.Port) == bp.Range() && string(realPort.PortProto) == bp.Protocol { ok = true; break }
        }
        if !ok { t.Errorf("Expect port %s, but exist in %v", bp.toTag(), service.ServicePorts) }
    }

    jsnService = `{"name": "example", "ports": ["65566", "2:3", "4:5/udp", {"port":"11:22"}]}`
	service, err = LegacyServiceFromJson([]byte(jsnService))
	if err == nil { t.Errorf("Expect exception, since bad port in json: %s", jsnService); return }
}

func TestTag(t *testing.T) {
	expected := map[string]string{"11":"udp", "0:65535":"tcp"}
	for k, v := range expected {
		port := &legacyBefwPort{
			Port: portRange(k),
			PortProto: befwServiceProto(v),
		}
		expected := fmt.Sprintf("%s/%s", k, v)
		if port.toTag() != expected { t.Errorf("Wrong tag '%s'; Expected: '%s'", port.toTag(), expected) }
	}

	tags := []string{"11/tcp", "12/udp", "1:42/tcp", "1:65535/udp"}
	for _, tag := range tags {
		newPort, err := PortFromTag(tag)
		if err != nil || newPort == nil { t.Errorf("Failed PortFromTag result") }
		p := strings.Split(tag, "/")
		if string(newPort.Port) != p[0] || string(newPort.PortProto) != p[1] { t.Errorf("Wrong parsed port and proto: %s %s", newPort.Port, newPort.PortProto) }
	}

	bads := []string{"", "0/tcp", "2:65536/udp", "0:65535/tcp", "33/xdp"}
	for _, tag := range bads {
		port, err := PortFromTag(tag)
		if err == nil || port != nil { t.Errorf("Expected error for bad tag %s", tag) }
	}
}
