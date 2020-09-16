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

import "testing"

func TestState(t *testing.T) {

}

func TestGenerateKVPaths(t *testing.T) {
	s1 := &state{
		nodeDC:   "ed",
		nodeName: "ed-sl-a126",
	}
	p1 := s1.generateKVPaths("test")
	s2 := &state{
		nodeDC:   "ed",
		nodeName: "ed-sl-a126.be.core.pw",
	}
	p2 := s2.generateKVPaths("test")
	if len(p1) != 6 {
		t.Error("Len != 3 in p1")
	}
	if len(p2) != 6 {
		t.Error("Len != 3 in p2")
	}
}

func TestWhitelistConst(t *testing.T) {
	s := &state{}
	s.applyWhitelistIPSet()
	if s.IPSets == nil {
		t.Error("state.IPSets is nil")
	}
	isLocalhost := false
	is10Net := false
	if v, ok := s.IPSets[allowIPSetName]; ok {
		for _, set := range v {
			switch set {
			case "10.0.0.0/8":
				is10Net = true
			case "192.168.0.0/16":
				isLocalhost = true
			}
		}
	} else {
		t.Error("state.IPSets[ allowIPSetName ] is not exists")
	}
	if !is10Net || !isLocalhost {
		t.Error("state.IPSets[ allowIPSetName ] must contain 10.0.0.0/8 and 192.168.0.0/16")
	}
}
