/**
 * Copyright 2018-2023 Wargaming Group Limited
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
	"encoding/gob"
	"github.com/wgnet/befw/logging"
	"io/ioutil"
	"os"
)

func recoverLastState(configFile string) *state {
	var ret state
	var e error
	var f *os.File
	if f, e = os.Open(befwStateBin); e == nil {
		d := gob.NewDecoder(f)
		if e = d.Decode(&ret); e == nil {
			return &ret
		}
	}
	logging.LogWarning("recoverLastState() error: ", e.Error())
	// gen new state
	ret.Config = createConfig(configFile)
	ret.NodeServices = make([]bService, 0)
	logging.LogInfo("recoverLastState(): returning default state")
	return &ret
}

func (state *state) saveLastState() {
	var b bytes.Buffer
	var err error
	e := gob.NewEncoder(&b)
	if err = e.Encode(state); err != nil {
		logging.LogWarning("saveLastState() failed: ", err.Error())
		return
	}
	if err = ioutil.WriteFile(befwStateBin, b.Bytes(), 0600); err != nil {
		logging.LogWarning("saveLastState() failed: ", err.Error())
	}
}
