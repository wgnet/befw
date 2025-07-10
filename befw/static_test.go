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
	"bytes"
	"net"
	"testing"
)

func TestPath2str(t *testing.T) {
	expected := map[string]string{
		"/befw/$alias$/$abc$/$sub_alias-1$":                      "$sub_alias-1$",
		"/befw/$alias$/$abc$/1.2.3.4/5":                          "1.2.3.4/5",
		"/befw/$alias$/$abc$/1.2.3.4":                            "1.2.3.4/32",
		"/befw/$alias$/$abc$/2003:dead:beef:4dad:23:46:bb:101/5": "2003:dead:beef:4dad:23:46:bb:101/5",
		"/befw/$alias$/$abc$/2003:dead:beef:4dad:23:46:bb:101":   "2003:dead:beef:4dad:23:46:bb:101/128",
	}
	wrong := []string{
		"/befw/$alias$/$abc$/1.2.3.4.5",
		"/befw/$alias$/$abc$/1.2.3.4/33",
		"/befw/$alias$/$abc$/text",
		"/befw/$alias$/$abc$/xxxx:2003:dead:beef:4dad:23:46:bb:101",
	}
	for k, v := range expected {
		if r := path2netpart(k); r != v {
			t.Error("Expected as valid net-string: ", k, " => ", r, " expect: ", v)
		}
	}
	for _, k := range wrong {
		if v := path2netpart(k); v != "" {
			t.Error("Should not be parsed as string: ", k, " =/=> ", v)
		}
	}
}

func TestNet2Strings(t *testing.T) {
	table := map[*net.IPNet]string{
		{
			IP:   net.IPv4(192, 168, 0, 5),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		}: "192.168.0.0/24",
		{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.IPv4Mask(255, 255, 255, 255),
		}: "192.168.0.1/32",
	}
	keys := make([]*net.IPNet, 0)
	values := make([]string, 0)
	for k, v := range table {
		keys = append(keys, k)
		values = append(values, v)
	}
	for i, x := range nets2string(keys) {
		if values[i] != x {
			t.Errorf("Value for %d doesn't match: %s != %s", i, x, values[i])
		}
	}
}

func TestPath2ipnet(t *testing.T) {
	table := map[string]*net.IPNet{
		"befw/$ipset$/rules_deny/1.20.209.254": {
			IP:   net.IPv4(1, 20, 209, 254),
			Mask: net.IPv4Mask(255, 255, 255, 255),
		},
		"befw/$alias$/$test$/192.168.0.5/24": {
			IP:   net.IPv4(192, 168, 0, 0),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		"befw/sercvice_tcp_2200/192.168.0.5": {
			IP:   net.IPv4(192, 168, 0, 5),
			Mask: net.IPv4Mask(255, 255, 255, 255),
		},
		"befw/sercvice_tcp_2200/10.0.0.5/8": {
			IP:   net.IPv4(10, 0, 0, 0),
			Mask: net.IPv4Mask(255, 0, 0, 0),
		},
		"befw/sercvice_tcp_2200/::1:5ee:bad:c0de/96": {
			IP:   net.IP{0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x05, 0xee, 0, 0, 0, 0},
			Mask: net.CIDRMask(96, 128),
		},
		"befw/sercvice_tcp_2200/cafe:feed::/127": {
			IP:   net.IP{0xca, 0xfe, 0xfe, 0xed, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Mask: net.CIDRMask(127, 128),
		},
		"befw/sercvice_tcp_2200/::/0": {
			IP:   net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Mask: net.CIDRMask(0, 128),
		},
	}
	equals := func(a, b *net.IPNet) bool {
		return a.IP.Equal(b.IP) && bytes.Equal([]byte(a.Mask), []byte(b.Mask))
	}
	for i, x := range table {
		if n := path2ipnet(i); n == nil || !equals(n, x) {
			t.Errorf("Value for %s doesn't match: %s != %s", i, x.String(), n)
		}
	}

}
