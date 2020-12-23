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
package logging

import (
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"runtime"
	"strconv"
)

var syslogWriter *syslog.Writer = nil

func prefix(message ...interface{}) string {
	var prefix string
	if _, file, line, ok := runtime.Caller(4); ok {
		for i := 0; i < len(file); i++ {
			if file[i] == '/' {
				file = file[i+1:]
			}
		}
		prefix = string(append(append([]byte(file), ':'), []byte(strconv.Itoa(line))...))
	} else {
		prefix = "unknown:0"
	}
	return fmt.Sprintf("[%s] %s", prefix, fmt.Sprint(message...))
}
func logMessageSyslog(level syslog.Priority, message ...interface{}) {
	if syslogWriter == nil {
		var e error
		if syslogWriter, e = syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "befw"); e != nil {
			logMessageStdout(level, message...)
			return
		}
	}
	m := prefix(message...)
	switch level {
	case syslog.LOG_DEBUG:
		if os.Getenv("BEFW_DEBUG") == "DEBUG" {
			syslogWriter.Debug(m)
		}
	case syslog.LOG_INFO:
		syslogWriter.Info(m)
	case syslog.LOG_ERR, syslog.LOG_ALERT, syslog.LOG_CRIT, syslog.LOG_EMERG:
		syslogWriter.Err(m)
	case syslog.LOG_WARNING:
		syslogWriter.Warning(m)
	}
}

func logMessage(level syslog.Priority, message ...interface{}) {
	if os.Getenv("BEFW_DEBUG") == "DEBUG" {
		logMessageStdout(level, message...)
	} else {
		logMessageSyslog(level, message...)
	}
}

func logMessageStdout(level syslog.Priority, message ...interface{}) {
	var l string
	switch level {
	case syslog.LOG_DEBUG:
		l = "DEBUG"
	case syslog.LOG_INFO:
		l = "INFO"
	case syslog.LOG_ERR:
		l = "ERR"
	case syslog.LOG_WARNING:
		l = "WARN"
	}
	println("[", l, "]", prefix(message...))
}

func LogError(message ...interface{}) {
	logMessage(syslog.LOG_ERR, message...)
	// panic
	panic(errors.New(fmt.Sprint(message...)))
}

func LogWarning(message ...interface{}) {
	logMessage(syslog.LOG_WARNING, message...)
}

func LogInfo(message ...interface{}) {
	logMessage(syslog.LOG_INFO, message...)
}

func LogDebug(message ...interface{}) {
	logMessage(syslog.LOG_DEBUG, message...)
}
