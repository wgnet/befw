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
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/wgnet/befw/logging"
	"os"
	"sort"
	"time"
)

func restoreStatus() {
	e := recover()
	if e != nil {
		if err, ok := e.(error); ok {
			logging.LogWarning("Panic! Recovering self from:", err.Error())
		} else {
			logging.LogWarning("Panic! Recovering self from:", e)
		}
		time.Sleep(time.Minute)
	}
}

func startService(configFile string) {
	defer restoreStatus()
	os.MkdirAll(befwState, 0755)
	startChecker()
	var errorCounts = 0
	for {
		s, e := refresh(configFile)
		if e != nil {
			errorCounts += 1
			if errorCounts > 10 {
				errorCounts = 10 // maximum of 5 minutes
			}
			sleepTime := errorCounts * 40
			logging.LogWarning("Error while refresh():", e, "; sleeping for ", sleepTime, " seconds")
			time.Sleep(time.Duration(sleepTime) * time.Second)
			continue
		} else {
			errorCounts = 0 // reset
		}
		if s != nil {
			sleepIfNoChanges(s)
		}
	}
}

func StartService(configFile string) {
	go startAPIServer()
	go nidsChecker()
	for {
		startService(configFile)
	}
}

func startChecker() {
	go func() {
		for {
			fw.KeepConsistent()
			time.Sleep(3 * time.Second)
		}
	}()
}
func GenerateConfigs() string {
	rules := defaultRules()
	data, err := json.MarshalIndent(&rules, "", " ")
	if err != nil {
		logging.LogError("Can't marshall default Config rules")
	}
	return string(data)
}

func ShowState(configFile string) string {
	rules, err := showState(configFile)
	if err != nil {
		return fmt.Sprint("ERROR: Can't generate data", err.Error())
	}
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "Node: %s @ %s\n\n", rules["*NodeName"][0], rules["*NodeDC"][0])
	delete(rules, "*NodeDC")
	delete(rules, "*NodeName")
	keys := make([]string, 0, len(rules))
	for k := range rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, s := range keys {
		fmt.Fprintf(buf, "- Service: %s\n", s)
		for _, ip := range rules[s] {
			fmt.Fprintf(buf, "--- %s\n", ip)
		}
		fmt.Fprintf(buf, "\n\n")
	}
	return buf.String()
}
