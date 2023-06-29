
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
    "strings"
	"testing"
)

func TestPort(t *testing.T) {
    var good []string = []string{"123", "123:234", "10/tcp", "10:100/udp", "33/udp", "42/TcP"}
    for _, raw := range good {
        p, e := NewBPort(raw)
        if p == nil { t.Errorf("Unexpected nil for %s", raw);continue }
        if e != nil { t.Errorf("Unexpected error for %s: %s", raw, e.Error()); continue }
        tag := p.toTag()
        if !strings.EqualFold(tag, raw) && !strings.EqualFold(tag, raw + "/tcp") {
            t.Errorf("Not equal tag: %s, but expected %s ", p.toTag(), raw) 
        }
    }
}
func TestBadPort(t *testing.T) {
    var bad []string = []string{"0", "-123:234", "10/xcp", "10:65536/udp", "-12/udp", "65537/TcP"}
    for _, raw := range bad {
        p, e := NewBPort(raw)
        if p != nil { t.Errorf("Expected nil but %s for %s", p.toTag(), raw);continue }
        if e == nil { t.Errorf("Expected error: %s", raw);continue }
    }
}

func TestIntersectPorts(t *testing.T) {
    // Intersected
    yes := []struct{
        a   string
        b   string
    }{ {"10", "1:100"}, {"10:20", "15:100"}, {"10:20", "1:15"},
       {"10:20", "1:100"}, {"10", "10:100"}, {"100:101", "10:100"}, {"42", "42"} }
    for _, i := range yes {
        pA, _ := NewBPort(i.a)
        pB, _ := NewBPort(i.b)
        if !pA.IsIntersect(pB) { t.Errorf("Expect intersected: %s - %s", pA.toTag(), pB.toTag());continue}
        if !pB.IsIntersect(pA) { t.Errorf("Expect intersected: %s - %s", pB.toTag(), pA.toTag());continue}
    }
    // Not intersected
    no := []struct{
        a   string
        b   string
    }{ {"10", "15:100"}, {"10:20", "30:100"}, {"10:20", "1:9"},
       {"42", "43"}, {"42", "42/udp"} }
    for _, i := range no {
        pA, _ := NewBPort(i.a)
        pB, _ := NewBPort(i.b)
        if pA.IsIntersect(pB) { t.Errorf("Expect NOT intersected: %s - %s", pA.toTag(), pB.toTag());continue}
        if pB.IsIntersect(pA) { t.Errorf("Expect NOT intersected: %s - %s", pB.toTag(), pA.toTag());continue}
    }
}
