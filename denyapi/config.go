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
	"bufio"
	"errors"
	"fmt"
	"github.com/wgnet/befw/logging"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

type denyConfig struct {
	ConsulToken    string        `config:"token"`
	ConsulAddress  string        `config:"address"`
	ConsulDC       string        `config:"dc"`
	Timeout        time.Duration `config:"timeout"`
	KeysURL        string        `config:"fetchkeys"`
	KeyURL         string        `config:"fetchkey"`
	GitRepoPath    string        `config:"gitrepo"`
	RootKeys       []uint64      `config:"rootkeys"`
	StopList       []*net.IPNet  `config:"stoplist"`
	Mask           int           `config:"minmask"`
	Expiry         time.Duration `config:"maxexpiry"`
	RepoRemote     string        `config:"remote"`
	RepoPGPKey     string        `config:"pgpkey"`
	RepoPGPKeyPass string        `config:"pgpkeypass"`
	RepoSSHKey     string        `config:"sshkey"`
	RepoSSHKeyPass string        `config:"sshkeypass"`
}

func defaultConfig() *denyConfig {
	return &denyConfig{
		KeysURL:     "https://sks/pks/lookup?op=index&search=company.com",
		KeyURL:      "https://sks/pks/lookup?op=get&search=%s",
		RootKeys:    []uint64{},
		StopList:    []*net.IPNet{},
		Mask:        24,
		Expiry:      24 * time.Hour,
		GitRepoPath: ".",
		Timeout:     30 * time.Second,
		RepoRemote:  "origin",
	}
}

var config = defaultConfig()

func (conf *denyConfig) updateConfig(configFile string) error {
	kv := make(map[string]string)
	if configFile == "" {
		return errors.New("configFile is empty")
	}
	confType := reflect.TypeOf(conf).Elem()
	getTagByFieldName := func(field string) string {
		if f, ok := confType.FieldByName(field); ok {
			if v, ok := f.Tag.Lookup("config"); ok {
				return v
			} else {
				return strings.ToLower(f.Name)
			}
		} else {
			return field
		}
	}
	setString := func(ptr *string, kv *map[string]string, key string) {
		if v, ok := (*kv)[getTagByFieldName(key)]; ok {
			*ptr = v
		}
	}
	setInt := func(ptr *int, kv *map[string]string, key string) {
		if v, ok := (*kv)[getTagByFieldName(key)]; ok {
			if v2, e := strconv.Atoi(v); e == nil {
				*ptr = v2
			}
		}
	}
	setDuration := func(ptr *time.Duration, kv *map[string]string, key string) {
		if v, ok := (*kv)[getTagByFieldName(key)]; ok {
			if d, e := time.ParseDuration(v); e == nil {
				*ptr = d
			}
		}
	}
	setNetIpNetPtrArray := func(ptr *[]*net.IPNet, kv *map[string]string, key string) {
		if v, ok := (*kv)[getTagByFieldName(key)]; ok {
			r := make([]*net.IPNet, 0)
			for _, part := range strings.Split(v, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				if !strings.ContainsAny(part, "/") {
					part += "/32"
				}
				if _, n, e := net.ParseCIDR(part); e == nil {
					r = append(r, n)
				}
			}
			*ptr = r
		}
	}
	setUint64array := func(ptr *[]uint64, kv *map[string]string, key string) {
		if v, ok := (*kv)[getTagByFieldName(key)]; ok {
			r := make([]uint64, 0)
			for _, part := range strings.Split(v, ",") {
				part = strings.ToLower(strings.TrimSpace(part))
				if part == "" {
					continue
				}
				base := 10
				start := 0
				if strings.HasPrefix(part, "0x") {
					base = 16
					start = 2
				} else if strings.ContainsAny(part, "abcdef") {
					base = 16
				}
				if x, e := strconv.ParseUint(part[start:], base, 64); e == nil {
					r = append(r, x)
				}
			}
			*ptr = r
		}
	}
	if f, e := os.Open(configFile); e != nil {
		logging.LogWarning("[denyConfig] can't open", configFile, ":", e.Error())
		return e
	} else {
		defer f.Close()
		r := bufio.NewScanner(f)
		for r.Scan() {
			l := r.Text()
			if !strings.HasPrefix(l, "#") {
				if strings.IndexByte(l, '=') > 0 {
					v2 := strings.Split(l, "=")
					kv[strings.Trim(v2[0], "\r\n\t ")] = strings.Trim(strings.Join(v2[1:], "="), "\r\n\t ")
				}
			}
		}
	}
	/**
	You may think it's a dark magic here. It's true.
	But it's better to write this once than fixing configuration in ten places
	Keep calm and do ((void(*)())0)();
	*/
	for i := 0; i < confType.NumField(); i++ {
		name := confType.Field(i).Name
		field := reflect.ValueOf(conf).Elem().Field(i)
		if !field.CanAddr() {
			continue
		}
		ptr := unsafe.Pointer(field.UnsafeAddr())
		switch field.Interface().(type) {
		case string:
			setString((*string)(ptr), &kv, name)
		case int:
			setInt((*int)(ptr), &kv, name)
		case []uint64:
			setUint64array((*[]uint64)(ptr), &kv, name)
		case []*net.IPNet:
			setNetIpNetPtrArray((*[]*net.IPNet)(ptr), &kv, name)
		case time.Duration:
			setDuration((*time.Duration)(ptr), &kv, name)

		}
	}
	return nil
}

func (conf *denyConfig) dump() string {
	return fmt.Sprintf("%+v\n", *conf)
}

func MakeConfig(configFile string) {
	if e := config.updateConfig(configFile); e != nil {
		logging.LogError(e.Error())
	}
}
