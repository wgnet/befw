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

import "testing"

func TestCutIPSet(t *testing.T) {
	table := map[string]string{
		"test_tcp_2200": "test_tcp_2200",
		"very_long_service_name_abcd_1234_tcp_2200": "ve_lo_se_na_ab_12_tc_2200",
	}
	for i, x := range table {
		if v := correctIPSetName(i); v != x {
			t.Error("correctIPSetName: ", i, "->", v, "!=", x)
		}
	}
}

func TestGetRandomString(t *testing.T) {
	for i := 0; i < 255; i++ {
		if v := getRandomString(); len(v) != 25 {
			t.Error("Non-25 string:", v)
		}
	}
}

func TestGetBinary(t *testing.T) {
	// get default binaries for any *nix
	testCases := []string{
		"sh", "cat", "ls",
	}
	for _, k := range testCases {
		if getBinary(k) == "false" {
			t.Error("can't find binary ", k)
		}
	}
}
