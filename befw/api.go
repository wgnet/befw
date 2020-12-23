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
package befw

import (
	"bufio"
	"fmt"
	"github.com/wgnet/befw/logging"
	"net"
	"os"
	"strings"
	"time"
)

type apiFunction func(...string) string

var apiCalls = map[string]apiFunction{
	"helo":          heloApiFunc,
	"help":          helpApiFunc,
	"reload":        reloadApiFunc,
	"clear_missing": cleanMissingApiFunc,
}

func SendApiCommand(command string) string {
	if c, e := net.Dial("unix", befwStateSocket); e != nil {
		return e.Error()
	} else {
		defer c.Close()
		reader := bufio.NewReader(c)
		c.Write([]byte(fmt.Sprintf("%s\n", strings.Trim(command, "\n\r "))))
		if ok, e := reader.ReadString('\n'); e != nil {
			return e.Error()
		} else {
			return strings.Trim(ok, "\r\n")
		}

	}
}
func helpApiFunc(arg ...string) string {
	return "helo;help;reload;clear_missing;"
}

func reloadApiFunc(arg ...string) string {
	notifyChannel <- nil // do refresh
	return "ok"
}

func cleanMissingApiFunc(arg ...string) string {
	cleanupMissing()
	return "ok"
}

func heloApiFunc(arg ...string) string {
	return "Hello, " + strings.Join(arg, " ")
}

func apiCallback(con net.Conn) {
	defer con.Close()
	reader := bufio.NewReader(con)
	for {
		con.SetDeadline(time.Now().Add(15 * time.Second))
		if cmd, e := reader.ReadString('\n'); e == nil {
			c := strings.Split(strings.Trim(cmd, "\n\r "), " ")
			if f, ok := apiCalls[c[0]]; ok {
				reply := f(c[1:]...)
				con.Write([]byte(reply + "\n"))
			} else {
				con.Write([]byte("command not found; type help for help\n"))
			}
		} else {
			return
		}
	}
}

func startAPIServer() {
	os.Remove(befwStateSocket)
	l, e := net.Listen("unix", befwStateSocket)
	if e != nil {
		logging.LogWarning("[API]: Can't run local socket: ", e.Error())
		return
	}
	if e := os.Chmod(befwStateSocket, 0666); e != nil {
		logging.LogWarning("[API]: Can't change mode of local socket: ", e.Error())
	}
	defer l.Close()
	ch := make(chan net.Conn, 10)
	go func() {
		for {
			con := <-ch
			go apiCallback(con)
		}
	}()

	for {
		if c, e := l.Accept(); e == nil {
			ch <- c
			logging.LogInfo("[API]: Got connection from:", c.RemoteAddr().String())
		} else {
			logging.LogWarning("[API]: Error accepting connection: ", e.Error())
		}
	}
}
