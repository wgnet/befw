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
	"errors"
	"fmt"
	"log/syslog"
)

var syslogWriter *syslog.Writer = nil

func logMessageSyslog(level syslog.Priority, message ...interface{}) {
	if syslogWriter == nil {
		var e error
		if syslogWriter, e = syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, packageName); e != nil {
			logMessageStdout(level, message...)
			return
		}
	}
	m := fmt.Sprint(message...)
	switch level {
	case syslog.LOG_DEBUG:
		if ConfigurationRunning == DebugConfiguration {
			syslogWriter.Debug(m)
		}
		break
	case syslog.LOG_INFO:
		syslogWriter.Info(m)
		break
	case syslog.LOG_ERR, syslog.LOG_ALERT, syslog.LOG_CRIT, syslog.LOG_EMERG:
		syslogWriter.Err(m)
		break
	case syslog.LOG_WARNING:
		syslogWriter.Warning(m)
		break
	default:
		break

	}
}

func logMessage(level syslog.Priority, message ...interface{}) {
	if ConfigurationRunning == DebugConfiguration {
		logMessageStdout(level, message...)
	} else {
		logMessageSyslog(level, message...)
	}
}

func logMessageStdout(level syslog.Priority, message ...interface{}) {
	fmt.Println(message...)
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
	logMessageStdout(syslog.LOG_DEBUG, message...)
}
