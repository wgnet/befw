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
)


func TestUnmarshalJson(t *testing.T) {
	// Basic json
	jsnService := "{\"name\":\"example\", \"protocol\":\"tcp\", \"port\":12345}"
	service, err := ServiceFromJson([]byte(jsnService))
	if err != nil { t.Errorf("Failed to unmarshal: %s", err);return }
	if service.ServiceName != "example" { t.Errorf("Bad name: %s != %s", service.ServiceName, "example") }
	if service.ServicePort != 12345 { t.Errorf("Bad port") }
	if service.ServiceProtocol != "tcp" { t.Errorf("Bad protocol") }

	// With ports and range
	jsnService = "{\"name\":\"example\", \"protocol\":\"tcp\", \"port\":12345, \"ports\":[{\"port\":\"1:42\", \"protocol\":\"udp\"}]}"
	service, err = ServiceFromJson([]byte(jsnService))
	if err != nil { t.Errorf("Failed to unmarshal: %s", err);return }
	if service.ServiceName != "example" { t.Errorf("Bad name: %s != %s", service.ServiceName, "example") }
	if service.ServicePort != 12345 { t.Errorf("Bad port") }
	if service.ServiceProtocol != "tcp" { t.Errorf("Bad protocol") }
	if len(service.ServicePorts) != 1 && string(service.ServicePorts[0].Port) != "1:42" { t.Errorf("Bad ports unmarshalling") }

	// TODO: with bad port/range

	// Default port, protocol from ports
	jsnService = "{\"name\":\"example\", \"ports\":[{\"port\":\"11:42\", \"protocol\":\"udp\"}]}"
	service, err = ServiceFromJson([]byte(jsnService))
	if err != nil { t.Errorf("Failed to unmarshal: %s", err); return }
	if service.ServiceName != "example" { t.Errorf("Bad name: %s != %s", service.ServiceName, "example") }
	if service.ServicePort != 11 { t.Errorf("Bad port") }
	if service.ServiceProtocol != "udp" { t.Errorf("Bad protocol") }

	// No ports, No port - wrong
	jsnService = "{\"name\":\"example\", \"ports\":[]}"
	service, err = ServiceFromJson([]byte(jsnService))
	if err == nil || service != nil { t.Errorf("Expected FAIL on unmarshalling bad JSON") }
}

func TestBadBad(t *testing.T) {
	//t.Errorf("Ok!")
}

