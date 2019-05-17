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
package puppetdbsync

import (
	"github.com/hashicorp/consul/api"
	"net/http"
	"sync"
)

type syncConfig struct {
	url           string
	verify        bool
	consulAddr    string
	consulDC      string
	commitToken   string
	nodeName      string
	nodeAddr      string
	sessionID     string
	httpClient    *http.Client
	consulClient  *api.Client
	cache         *hotCache
	cacheMutex    *sync.RWMutex
	services      map[string]int64
	servicesMutex *sync.RWMutex
	servicesWG    *sync.WaitGroup
}

type syncData struct {
	service string
	dc      string
	node    string
	value   string
}

type hotCache struct {
	dcs   map[string]interface{}
	nodes map[string]interface{}
	error bool
}