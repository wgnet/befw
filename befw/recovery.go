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
	"fmt"
	"os"
)

func PanicRecovery() {
	if e := recover(); e != nil {
		var r string
		switch e.(type) {
		case error:
			r = e.(error).Error()
		case string:
			r = e.(string)
		default:
			r = fmt.Sprint(e)

		}
		fmt.Fprintf(os.Stderr, "FATAL ERROR: %s\n", r)
	}
	os.Exit(1)
}
