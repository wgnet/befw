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
package denyapi

import (
	"errors"
	"fmt"
	"github.com/hashicorp/consul/api"
	"github.com/wgnet/befw/logging"
	"net"
	"time"
)

type UserInfo struct {
	Name  string
	Email string
	KeyID uint64
}

type DenyRecord struct {
	Address   *net.IPNet
	Reason    string
	Expiry    time.Time
	Committer *UserInfo
}

func (user *UserInfo) String() string {
	return fmt.Sprintf("UI{%s <%s> keyid 0x%016X}", user.Name, user.Email, user.KeyID)
}

func (record *DenyRecord) String() string {
	return fmt.Sprintf("DenyRecord{%s [%d => %d] @ %s // %s}",
		record.Address.String(),
		time.Now().Unix(), record.Expiry.Unix(), record.Committer.String(), record.Reason)
}

func doBan(record *DenyRecord) error {
	if client != nil {
		_, e := client.KV().Put(&api.KVPair{
			Key:   fmt.Sprintf("befw/$ipset$/rules_deny/%s", record.Address.String()),
			Value: []byte(fmt.Sprintf("%d", record.Expiry.Unix())),
		},
			nil,
		)
		if e == nil {
			go replyCommit(record)
			logging.LogInfo("[DenyAPI] ban applied: ", record)
		} else {
			return e
		}
	} else {
		return errors.New("[DenyAPI] consul client is not initialized")
	}
	return nil
}

var client *api.Client

func Run() {
	var e error
	conf := api.DefaultConfig()
	conf.Address = config.ConsulAddress
	conf.Datacenter = config.ConsulDC
	conf.Token = config.ConsulToken
	if client, e = api.NewClient(conf); e == nil {
		conf.HttpClient.Timeout = config.Timeout
	} else {
		logging.LogError("[DenyAPI] consul client setup failed: ", e.Error())
	}
	if e = prepareSignKey(); e != nil {
		logging.LogError("[DenyAPI] pgp setup failed: ", e.Error())
	}
	pgpcache.refresh()
	go func() {
		for {
			time.Sleep(15 * time.Minute) // guaranteed timeout for new keys
			pgpcache.refresh()
		}
	}()
	for {
		if e := runGit(doBan); e != nil {
			logging.LogWarning("[DenyAPI] runGit failed: ", e.Error())
		} else {
			logging.LogDebug("[DenyAPI] runGit completed")
		}
		time.Sleep(30 * time.Second)
	}
}
