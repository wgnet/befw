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
package puppetdbsync

import (
	"sync"
	"testing"
)

func TestNewSyncData(t *testing.T) {
	conf := &syncConfig{
		cache: &hotCache{
			dcs:   map[string]interface{}{"dc1": nil, "dc2": nil},
			nodes: map[string]interface{}{"dc1@node1": nil, "dc2@node2": nil},
			error: false,
		},
		cacheMutex: new(sync.RWMutex),
	}
	table := map[string]bool{
		"ssh_tcp_22@192.168.0.0/24":                 true,
		"ssh_tcp_22@192.168.0.0":                    true,
		"ssh@192.168.0.0":                           false,
		"ssh_test_tcp_2222@192.168.0.0":             true,
		"test_test_test_test_udp_80@192.168.0.0":    true,
		"test_test_test_test_udp_80000@192.168.0.0": false,
		"ssh_tcp_22@dc1@node1@192.168.0.0":          true,
		"ssh_tcp_22@dc1@node2@192.168.0.0":          false,
		"ssh_tcp_22@256.168.0.0/24":                 false,
		"ssh_tcp_22@256.168.0.0":                    false,
		"ssh_tcp_22@dc2@192.168.0.0":                true,
		"node1@ssh_tcp_22@192.168.0.0":              false,
		"ssh_tcp_22@$alias$":                        true,
		"ssh_tcp_22@$alias":                         false,
	}

	for data, expected := range table {
		v := conf.newSyncData(data)
		if (v != nil) != expected {
			t.Errorf("Result of testing (%s) was incorrect: %v != %v",
				data, expected, v != nil)
		}
	}

}
