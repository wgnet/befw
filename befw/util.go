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
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	REGEXP_IP4_SEG = "(?:25[0-5]|2[0-4][0-9]|(?:1[0-9]|[1-9])?[0-9])"
	REGEXP_IP4     = "(?:" + REGEXP_IP4_SEG + "\\.){3}" + REGEXP_IP4_SEG

	REGEXP_IP6_SEG   = "(?:[0-9a-fA-F]{1,4})"
	REGEXP_IP6_SEG_L = "(?::" + REGEXP_IP6_SEG + ")"
	REGEXP_IP6_SEG_R = "(?:" + REGEXP_IP6_SEG + ":)"
	REGEXP_IP6       = "(?:" + REGEXP_IP6_SEG_R + "{7}" + REGEXP_IP6_SEG + "|" + // a:b:c:d:e:f:0:1
		REGEXP_IP6_SEG_R + "{1,7}:" + "|" + // a:b:c::
		":" + REGEXP_IP6_SEG_L + "{0,7}" + "|" + // ::a:b
		"::|" + // ::
		REGEXP_IP6_SEG_R + "{1,6}" + REGEXP_IP6_SEG_L + "{1}|" + // a:b:c:d:e:f::1
		REGEXP_IP6_SEG_R + "{1,5}" + REGEXP_IP6_SEG_L + "{1,2}|" + //    ...
		REGEXP_IP6_SEG_R + "{1,4}" + REGEXP_IP6_SEG_L + "{1,3}|" +
		REGEXP_IP6_SEG_R + "{1,3}" + REGEXP_IP6_SEG_L + "{1,4}|" +
		REGEXP_IP6_SEG_R + "{1,2}" + REGEXP_IP6_SEG_L + "{1,5}|" +
		REGEXP_IP6_SEG_R + "{1}" + REGEXP_IP6_SEG_L + "{1,6}|" +
		")"

	REGEXP_NET_32  = "(?:/(?:3[0-2]|[12]?[0-9]))?"
	REGEXP_NET_128 = "(?:/(?:12[0-8]|(?:1[0-1]|[1-9])?[0-9]))?"

	REGEXP_IP4_NET = REGEXP_IP4 + REGEXP_NET_32
	REGEXP_IP6_NET = REGEXP_IP6 + REGEXP_NET_128
)

var randDict []byte

func dbg(msg ...interface{}) {
	fmt.Println(" [DBG] ", fmt.Sprint(msg...))
}

func getBinary(name string) string {
	// use pre-built path with right order
	path := []string{
		"/sbin",
		"/usr/sbin",
		"/bin",
		"/usr/bin",
		"/usr/local/sbin",
		"/usr/local/bin",
		"",
	}
	for _, p := range path {
		v := filepath.Join(p, name)
		if i, e := os.Stat(v); e == nil {
			if i.Mode()&0111 != 0 {
				return v
			}
		}
	}
	return "false" // command
}

func getRandomString() string {
	// random of 30
	if randDict == nil {
		randDict = make([]byte, 26*2+10)
		for i := 'A'; i <= 'Z'; i++ {
			randDict[i-'A'] = byte(i)
		}
		for i := 'a'; i <= 'z'; i++ {
			randDict[26+i-'a'] = byte(i)
		}
		for i := '0'; i <= '9'; i++ {
			randDict[52+i-'0'] = byte(i)
		}
	}
	v := make([]byte, 25)
	for i := 0; i < 25; i++ {
		v[i] = randDict[rand.Intn(len(randDict)-1)]
	}
	return string(v)
}

// Check if elem in array
func inArray(arr []string, elem string) bool {
	for _, r := range arr {
		if r == elem {
			return true
		}
	}
	return false
}

// Cut string to be ipset name
func correctIPSetName(ipsetName string) string {
	const MAX = 31
	if len(ipsetName) > MAX { // max size of links
		parts := strings.Split(ipsetName, "_")
		last := parts[len(parts)-1]
		leftLength := MAX - len(last) // we can't reduce last part
		maxPartLen := int(leftLength/(len(parts)-1) - 1)
		for i := 0; i < len(parts)-1; i++ {
			if len(parts[i]) > maxPartLen {
				parts[i] = string([]byte(parts[i])[0:maxPartLen]) // trim to size
			}
		}
		return strings.Join(parts, "_")
	} else {
		return ipsetName
	}
}

// Run binary command
// Example:
//
//	out, err := run(nil, "echo", "42")  // out == "42\n"
func run(stdin *string, params ...string) (string, error) {
	stdout := new(strings.Builder)
	//stdout.Reset()
	if len(params) <= 0 {
		return "", errors.New("Need command as argument")
	}
	cmd := exec.Command(getBinary(params[0]), params[1:]...)
	cmd.Stdout = stdout
	cmd.Stderr = stdout
	if stdin != nil {
		cmd.Stdin = strings.NewReader(*stdin)
	}

	err := cmd.Run()
	return stdout.String(), err
}

// Check if IP is v6 (source: stackoverflow 22751035)
func isIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}
