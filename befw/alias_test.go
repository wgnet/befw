/**
 * Copyright 2018-2025 Wargaming Group Limited
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
	"testing"
)

func TestAliasResolver(t *testing.T) {
	data := map[string][]string{
		"$a$": []string{"1", "$b$", "2"},
		"$b$": []string{"3", "$c$", "$a$", "4"},
		"$c$": []string{"5"},
	}
	fn_upd := func(key string) []string {
		return data[key]
	}

	ar := AliasResolver{
		cache:   make(map[string][]string),
		updater: fn_upd,
	}

	rs := ar.Resolve("$a$")
	for _, expected := range []string{"1", "2", "3", "4", "5"} {
		ok := false
		for _, a := range rs {
			if a == expected {
				ok = true
				break
			}
		}
		if ok {
			continue
		}
		t.Error("Expected address not in resolve: ", expected, ", resolve: ", rs)
	}
}
