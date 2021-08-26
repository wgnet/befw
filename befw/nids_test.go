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

import (
	"fmt"
	"net"
	"testing"
)

func TestCheckPortIsUsed(t *testing.T) {
	ports := []int{9999, 44444, 33133, 8888}
	l, e := net.Listen("tcp", ":9999")
	if e != nil {
		t.Error(e.Error())
		return
	}
	defer l.Close()
	b1 := 0
	for _, p := range ports {
		b := nidsCheckPortIsInUse(p)
		if p == 9999 && b != true {
			t.Error("Port ", 9999, " is listening but not found")
		}
		if b == true {
			b1++
		}
	}
	if b1 == len(ports) {
		t.Error("All ports are used, is that true?!")
	}
}

func TestPickRandom50(t *testing.T) {
	ports := nidsGenerateRandomPorts()
	for _, p := range ports {
		l, e := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if e != nil {
			t.Error(e.Error())
		} else {
			l.Close()
		}
	}
}
