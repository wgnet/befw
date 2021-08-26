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
package puppetdbsync

import (
	"github.com/wgnet/befw/befw"
	"github.com/wgnet/befw/logging"
	"strconv"
	"time"
)

func (conf *syncConfig) wipeExpired() error {
	currentDate := time.Now().Unix()
	list, _, e := conf.consulClient.KV().List("befw", nil)
	if e != nil {
		return e
	}
	del := make(map[string]bool)
	for _, kv := range list {
		if !befw.BEFWRegexp.MatchString(kv.Key) {
			continue
		}
		expiryDate, e := strconv.ParseInt(string(kv.Value), 10, 64)
		if e != nil || (expiryDate > 0 && expiryDate < currentDate) { // some shit happen
			del[kv.Key] = true
		}
	}

	for k := range del {
		_, e := conf.consulClient.KV().Delete(k, nil)
		if e == nil {
			logging.LogInfo("[Syncer] wiping expired record: ", k)
		}
	}
	return nil
}

func runWipe(conf *syncConfig) {
	for {
		e := conf.wipeExpired()
		if e != nil {
			logging.LogError("[Syncer] wipeExpired filed: ", e.Error())
		}
		select {
		case <-exitChan:
			logging.LogDebug("[Syncer] wiper exiting...")
			return
		case <-time.After(time.Hour):
			continue
		}
	}
}
