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
package main

import (
	"flag"
	"time"
)
import "./befw"
import "./puppetdbsync"

func main() {
	config := flag.String("config", "/etc/befw.sync.conf", "BEFW-SYNC config file")
	debug := flag.Bool("debug", false, "StartService with debug configuration")
	timeout := flag.Duration("timeout", 10*time.Second, "Timeout between puppetdb re-query")
	flag.Parse()
	if *debug {
		befw.ConfigurationRunning = befw.DebugConfiguration
	} else {
		defer panicRecovery()
	}
	puppetdbsync.Run(*config, *timeout)
}
