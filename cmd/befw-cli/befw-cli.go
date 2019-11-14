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
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/wgnet/befw/befw"
)

var commands = map[string]func([]string) error{
	"register":   register,
	"deregister": deRegister,
	"reload":     reload,
	"refresh":    clearStats,
	"genrules":   genRules,
	"show":       showRules,
}

func genRules(args []string) error {
	if args[0] == "help" {
		fmt.Printf("Usage: %s genrules\n", os.Args[0])
		fmt.Printf("generates default befw.rules.json to standart output\n")
		return nil
	}
	println(befw.GenerateConfigs())
	return nil
}

func showRules(args []string) error {
	if args[0] == "help" {
		fmt.Printf("Usage: %s show\n", os.Args[0])
		fmt.Printf("shows current befw state ( services / rules )\n")
		return nil
	}
	println(befw.ShowState(configFile))
	return nil
}

func help(args []string) error {
	if len(args) >= 2 {
		if f, ok := commands[args[1]]; ok {
			f([]string{"help"}) // never ever can be so
			return nil
		} else {
			fmt.Printf("Help on %s not found\n", args[1])
		}
	}
	fmt.Printf("BEFW-CLI - a CLI tool for befw-firewalld\n")
	fmt.Printf("Usage: %s <command> [options]\n", os.Args[0])
	fmt.Printf("Help: %s help <command>\n", os.Args[0])
	fmt.Printf("Commands: ")
	_f := true
	for c, _ := range commands {
		if !_f {
			fmt.Printf(", ")
		} else {
			_f = false
		}
		fmt.Printf("%s", c)
	}
	fmt.Printf("\n")
	return nil
}

func register(args []string) error {
	if args[0] == "help" || len(args) != 4 {
		fmt.Printf("Usage: %s register <service name> <protocol> <port>\n", os.Args[0])
		fmt.Printf("Registers service on local consul agent\n")
		return nil
	}
	if v, e := strconv.Atoi(args[3]); e == nil {
		if e := befw.RegisterService(configFile, args[1], args[2], v); e == nil {
			fmt.Printf("Service registered\n")
		} else {
			return e
		}
	} else {
		return errors.New(fmt.Sprintf("Port must be integer value: ", e.Error()))
	}
	return nil
}

func deRegister(args []string) error {
	if args[0] == "help" || len(args) != 2 {
		fmt.Printf("Usage: %s del <service name>\n", os.Args[0])
		fmt.Printf("Deregisters service from local consul agent\n")
		return nil
	}
	if e := befw.DeregisterService(configFile, args[1]); e == nil {
		fmt.Printf("Service deregistered\n")
	} else {
		return e
	}
	return nil
}

func reload(args []string) error {
	if args[0] == "help" {
		fmt.Printf("Usage: %s reload\n", os.Args[0])
		fmt.Printf("Reloads befw rules from consul\n")
	}
	if s := befw.SendApiCommand("reload"); s == "ok" {
		fmt.Printf("Reloaded successfully\n")
	} else {
		return errors.New(s)
	}
	return nil
}

func clearStats(args []string) error {
	if args[0] == "help" {
		fmt.Printf("Usage: %s refresh\n", os.Args[0])
		fmt.Printf("Refreshes missing stats cache\n")
	}
	if s := befw.SendApiCommand("clear_missing"); s == "ok" {
		fmt.Printf("Missing stats were cleared\n")
	} else {
		return errors.New(s)
	}

	return nil
}

var configFile string

func main() {
	defer befw.PanicRecovery()
	flag.StringVar(&configFile, "config", "/etc/befw.conf", "Config file for befw")
	flag.Parse()
	var arg0 string
	if len(flag.Args()) == 0 {
		help(flag.Args())
		return
	} else {
		arg0 = flag.Arg(0)
	}
	if f, ok := commands[arg0]; ok {
		if e := f(flag.Args()); e != nil {
			panic(e)
		}
	} else {
		help(flag.Args())
		return
	}
}
