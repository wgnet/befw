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
package befw

import (
    "fmt"
    "strings"
    "strconv"
    "net"
)

const (
    PROTOCOL_TCP = "tcp"
    PROTOCOL_UDP = "udp"
    MAX_PORT = 65535
)

type netPort = uint16
type netProtocol = string

type bService struct {
    Name    string
    Ports   []bPort
    Clients []bClient
}

type bPort struct {
    From        netPort
    To          netPort
    Protocol    netProtocol
}

type bClient struct {                                                
    clientCIDR   *net.IPNet
    clientExpiry int64
}

func (s *bService) toString() string {
    return fmt.Sprintf("%s", s.Name)
}

// bPort functions =========================
func NewBPort(tag string) (*bPort, error) {
    var protocol netProtocol = PROTOCOL_TCP
    var from, to netPort
    // Protocol
    s := strings.Split(tag, "/")
    dport := strings.Split(s[0], ":")
    if len(s) > 2 || len(dport) > 2 { 
        return nil, fmt.Errorf("Expected port tag: <from>[:<to>][/<protocol>] (ex.: '80', '22:51/tcp'). But %s", tag) 
    }
    if len(s) == 2 {
        if strings.EqualFold(s[1], PROTOCOL_TCP) {
            protocol = PROTOCOL_TCP
        } else if strings.EqualFold(s[1], PROTOCOL_UDP) {
            protocol = PROTOCOL_UDP
        } else {
            return nil, fmt.Errorf("Expected protocol 'tcp' or 'udp', but %s", tag)
        }
    }

    // Port range
    for i, p := range dport {
        n, err := strconv.Atoi(p)
        if err != nil { return nil, err }
        if n > MAX_PORT || n <= 0 { return nil, fmt.Errorf("Expected port range 1-65535. But %s", tag) }
        if i == 0 { 
            from = netPort(n); to = from
        } else if i == 1 { to = netPort(n) }
    }

    return &bPort {
        From:       from,
        To:         to,
        Protocol:   protocol,
    }, nil
}


func (p *bPort) toTag() string {
    return fmt.Sprintf("%s/%s", p.Range(), p.Protocol)
}

func (p *bPort) Range() string {
    if p.To <= p.From {
        return fmt.Sprintf("%d", p.From)
    } else {
        return fmt.Sprintf("%d:%d", p.From, p.To)
    }
}


// Utils:

func (p *bPort) IsIntersect(o *bPort) bool {
    if p.From < o.From && p.To < o.From { return false } // If p.To <= p.From and p.From < o.From -->  p.To < o.From
    if o.From < p.From && o.To < p.From { return false } //  ... same
    if o.Protocol != p.Protocol { return false }
    return true
}
