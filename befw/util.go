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
    "os"
	"path/filepath"
	"strings"
	"math/rand"
)

var randDict []byte

func getBinary(name string) string {
	// use pre-built path with right order
	path := []string{
		"/sbin",
		"/usr/sbin",
		"/bin",
		"/usr/bin",
		"/usr/local/sbin",
		"/usr/local/bin",
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
	if len(ipsetName) > 31 { // max size of links
		parts := strings.Split(ipsetName, "_")
		leftLength := 31 - len(parts[len(parts)-1]) // we can't reduce last part
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
