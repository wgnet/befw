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
package main

import (
	"flag"
	"os"

	"github.com/wgnet/befw/logging"

	"github.com/wgnet/befw/befw"
)

func main() {
	debug := flag.Bool("debug", false, "StartService with debug configuration")
	nonflog := flag.Bool("nonflog", false, "Disable NF Logging")
	noroot := flag.Bool("noroot", false, "Allow run service as non-root user")
	timeout := flag.String("timeout", "", "Force refresh timeout")
	consulTimeout := flag.String("consulTimeout", "", "Consul HTTP connection timeout")
	config := flag.String("config", "/etc/befw.conf", "Config file for befw")
	nflogEventBuffer := flag.Int("nflogbuffer", 64*1024, "NFlog Event buffer")
	flag.Parse()

	if *debug {
		os.Setenv("BEFW_DEBUG", "DEBUG")
	} else {
		defer befw.PanicRecovery()
	}

	if *timeout != "" {
		befw.OverrideConfig["consul_timeout_sec"] = *timeout
	}
	if *consulTimeout != "" {
		befw.OverrideConfig["consulwatch_timeout_sec"] = *consulTimeout
	}

	if !*noroot && os.Getuid() != 0 {
		logging.LogError("You must be r00t to run as a service")
	}
	if !*nonflog {
		befw.StartNFLogger(*nflogEventBuffer)
		logging.LogInfo("NFLogger started, you can get information from /var/run/befw/*")
	}
	befw.StartService(*config)
}
