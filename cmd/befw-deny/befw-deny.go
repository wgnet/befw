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
	"github.com/wgnet/befw/befw"
	"github.com/wgnet/befw/denyapi"
	"os"
)

func main() {
	debug := flag.Bool("debug", false, "Run with debugging")
	config := flag.String("config", "/etc/befw.deny.conf", "Path to config file")
	flag.Parse()
	if *debug {
		os.Setenv("BEFW_DEBUG", "DEBUG")
	} else {
		defer befw.PanicRecovery()
	}
	denyapi.MakeConfig(*config)
	denyapi.Run()
}
