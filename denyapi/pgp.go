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
	"bytes"
	"errors"
	"fmt"
	"github.com/wgnet/befw/befw"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/net/html"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	pgpStartKeyBlock = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	pgpEndKeyBlock   = "-----END PGP PUBLIC KEY BLOCK-----"
)

type pgpCache struct {
	validArmoredKeyRing bytes.Buffer
	validRWMutex        sync.RWMutex
}

var pgpcache = new(pgpCache)

func (cache *pgpCache) refresh() {
	cache.validRWMutex.Lock()
	defer cache.validRWMutex.Unlock()
	oldCache := cache.validArmoredKeyRing.String()
	defer func() { // restore if we fail
		if cache.validArmoredKeyRing.Len() == 0 {
			cache.validArmoredKeyRing.WriteString(oldCache)
		}
	}()
	cache.validArmoredKeyRing.Reset()
	keys := getAllKeys()
	encoder, _ := armor.Encode(&cache.validArmoredKeyRing, openpgp.PublicKeyType, nil)
	validKeys := 0
	for key := range keys {
		if e := checkKeyIsEligible(key, config.RootKeys...); e != nil {
			e.Serialize(encoder)
			validKeys++
		}
	}
	encoder.Close()
	befw.LogDebug("[DenyAPI] Refreshing PGP cache - ", validKeys, " signed keys")
}

func (cache *pgpCache) verifyCommit(c *object.Commit) (ret bool, keyid uint64) {
	defer func() {
		befw.LogDebug("[DenyAPI] Verifying commit ", c.Hash.String(), ": ", ret)
	}()
	if c.PGPSignature == "" {
		return false, 0
	}
	cache.validRWMutex.RLock()
	defer cache.validRWMutex.RUnlock()
	if entity, e := c.Verify(cache.validArmoredKeyRing.String()); e == nil {
		return true, entity.PrimaryKey.KeyId
	}
	return false, 0
}

func getAllKeys() map[string]bool {
	ret := make(map[string]bool, 0)
	cli := http.Client{Timeout: config.Timeout}
	r, e := cli.Get(config.KeysURL)
	if e != nil {
		panic(e)
	}
	if r.StatusCode != 200 {
		return nil
	}
	tokenizer := html.NewTokenizer(r.Body)
	for {
		if tokenizer.Next() == html.ErrorToken {
			break
		}
		if tagName, hasAttrs := tokenizer.TagName(); string(tagName) == "a" && hasAttrs {
			for {
				attrName, attrValue, hasMore := tokenizer.TagAttr()
				if string(attrName) == "href" {
					for _, x := range strings.Split(string(attrValue), "=") {
						if strings.HasPrefix(x, "0x") {
							ret[x] = true
							break
						}
					}
				}
				if !hasMore {
					break
				}
			}
		}
	}
	return ret
}

func getPublicKeyById(id string) *openpgp.Entity {
	httpClient := http.Client{Timeout: config.Timeout}
	if r, e := httpClient.Get(fmt.Sprintf(config.KeyURL, id)); e != nil || r.StatusCode != 200 {
		return nil
	} else {
		scanner := bufio.NewScanner(r.Body)
		keybuf := new(bytes.Buffer)
		hasStart := false
		for scanner.Scan() {
			line := scanner.Text()
			if line == pgpStartKeyBlock || hasStart {
				hasStart = true
				keybuf.WriteString(line)
				keybuf.WriteByte('\n')
			}
			if line == pgpEndKeyBlock {
				keybuf.WriteByte('\n')
				break
			}
		}
		if el, e := openpgp.ReadArmoredKeyRing(keybuf); e != nil || len(el) == 0 {
			return nil
		} else {
			return el[0]
		}
	}
}

func checkKeyIsEligible(keyID string, rootkeys ...uint64) *openpgp.Entity {
	trustedMap := make(map[uint64]bool)
	for _, i := range rootkeys {
		trustedMap[i] = false
	}
	if entity := getPublicKeyById(keyID); entity != nil {
		for _, identity := range entity.Identities {
			if identity.SelfSignature == nil {
				continue // no self sig
			}
			if identity.SelfSignature.KeyExpired(time.Now()) {
				continue // idenitity is expired
			}
			if identity.SelfSignature.RevocationReason != nil {
				continue // identity is revoked
			}
			if _, ok := trustedMap[entity.PrimaryKey.KeyId]; ok { // one of trust keys itself
				return entity
			}
			for _, sign := range identity.Signatures {
				if _, ok := trustedMap[*sign.IssuerKeyId]; ok {
					trustedMap[*sign.IssuerKeyId] = true
				}
			}
		}

		for _, f := range trustedMap {
			if !f {
				return nil
			}
		}
		return entity
	}
	return nil
}

var signingEntity *openpgp.Entity

func prepareSignKey() error {
	if config.RepoPGPKey != "" {
		if fd, e := os.Open(config.RepoPGPKey); e == nil {
			if el, e := openpgp.ReadArmoredKeyRing(fd); e == nil {
				if len(el) > 0 {
					entity := el[0]
					if entity.PrivateKey == nil {
						return errors.New("no private key into `pgpkey` file")
					}
					if entity.PrivateKey.Encrypted {
						if config.RepoPGPKeyPass == "" {
							return errors.New("key is encrypted, but `pgpkeypass` is not set")
						}
						if e := entity.PrivateKey.Decrypt([]byte(config.RepoPGPKeyPass)); e != nil {
							return e
						}
						config.RepoPGPKeyPass = "" // remove from memory
					}
					// fast test
					signBuffer := new(bytes.Buffer)
					textBuffer := strings.NewReader("Copyright (C) Ivan Agarkov, 2020. Happy hacking!")
					if e := openpgp.DetachSignText(signBuffer, entity, textBuffer, new(packet.Config)); e != nil {
						return e
					}
					textBuffer.Seek(0, 0)
					if _, e := openpgp.CheckDetachedSignature(el, textBuffer, signBuffer); e != nil {
						return e
					}
					befw.LogDebug("[DenyAPI] PGP tests passed")
					signingEntity = entity
				} else {
					return errors.New("no entities provide inside `pgpkey` file")
				}
			} else {
				return e
			}
		} else {
			return e
		}

	} else {
		return errors.New("`pgpkey` is mandatory option")
	}
	return nil
}
