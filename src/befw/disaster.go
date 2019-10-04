package befw

import (
	"bytes"
	"encoding/gob"
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
	LogWarning("recoverLastState() error: ", e.Error())
	// gen new state
	ret.IPSets = make(map[string][]string)
	for _, conf := range staticIPSetList {
		ret.IPSets[conf.Name] = make([]string, 0)
	}
	ret.IPSets["rules_allow"] = append(ret.IPSets["rules_allow"], "10.0.0.0/8")
	ret.NodeServices = make([]service, 0)
	LogInfo("recoverLastState(): returning default state")
	ret.Config = createConfig(configFile)
	return &ret
}

func (state *state) saveLastState() {
	var b bytes.Buffer
	var err error
	e := gob.NewEncoder(&b)
	if err = e.Encode(state); err != nil {
		LogWarning("saveLastState() failed: ", err.Error())
		return
	}
	if err 	= ioutil.WriteFile(befwStateBin, b.Bytes(), 0600); err != nil {
		LogWarning("saveLastState() failed: ", err.Error())
	}
}
