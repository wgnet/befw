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
	"github.com/wgnet/befw/logging"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/transport"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/ssh"
	"net"
	"strings"
	"time"
)

func intersect(n1, n2 *net.IPNet) bool {
	return n2.Contains(n1.IP) || n1.Contains(n2.IP)
}

func commitLogDebug(commit *object.Commit, message ...interface{}) {
	hashLogDebug(&commit.Hash, message...)
}

func hashLogDebug(hash *plumbing.Hash, message ...interface{}) {
	logging.LogDebug(append([]interface{}{fmt.Sprintf("[DenyAPI][%s] ", hash.String()[:7])}, message...)...)
}

func checkCommit(commit *object.Commit, f func(record *DenyRecord) error) error {
	if s, _ := commit.Stats(); len(s) != 0 {
		// skip
		return nil
	}
	if commit.PGPSignature == "" {
		// skip
		return nil
	}
	denyRecord := new(DenyRecord)
	fields := strings.Split(strings.TrimSpace(commit.Message), " ")
	if _, n, e := net.ParseCIDR(fields[0]); e == nil {
		if o, _ := n.Mask.Size(); o < config.Mask {
			commitLogDebug(commit, "network ", fields[0], " has mask ", o, " min size is ", config.Mask)
			return nil
		}
		for _, wn := range config.StopList {
			if intersect(n, wn) {
				commitLogDebug(commit, "network ", fields[0], " is in stop list")
				return nil
			}
		}
		denyRecord.Address = n
	} else {
		commitLogDebug(commit, "field[0] is not a network")
		return nil
	}

	if d, e := time.ParseDuration(fields[1]); e == nil {
		if d > config.Expiry {
			commitLogDebug(commit, "Duration ", d.String(), " is more than maximum allowed ", config.Expiry.String())
			return nil
		}
		denyRecord.Expiry = commit.Committer.When.Add(d)
		if time.Now().After(denyRecord.Expiry) {
			commitLogDebug(commit, "Expiry date is already reached: ", denyRecord.Expiry)
			return nil
		}
	} else {
		commitLogDebug(commit, "Can't parse duration on ", fields[1], " - skipping")
		return nil
	}
	denyRecord.Reason = strings.Join(fields[2:], " ")
	if ok, id := pgpcache.verifyCommit(commit); ok {
		denyRecord.Committer = &UserInfo{
			Name:  commit.Committer.Name,
			Email: commit.Committer.Email,
			KeyID: id,
		}
		if f != nil {
			return f(denyRecord)
		} else {
			return errors.New("f is null")
		}
	}
	return nil
}

var commitChannel = make(chan string, 1000)

func commitGit(wt *git.Worktree, message string) error {
	if signingEntity == nil {
		return errors.New("PGP key is needed to commit")
	}
	// get primary idenitity
	var email, name string
	for _, id := range signingEntity.Identities {
		email = id.UserId.Email
		name = id.UserId.Name
		break
	}
	hash, e := wt.Commit(message, &git.CommitOptions{
		All: false,
		Author: &object.Signature{
			Name:  name,
			Email: email,
			When:  time.Now(),
		},
		Committer: nil,
		Parents:   nil,
		SignKey:   signingEntity,
	})
	if e == nil {
		hashLogDebug(&hash, "New commit: [", message, "]")
	}
	return nil
}

func afterRun(repository *git.Repository) {
	wt, _ := repository.Worktree()
	eof := false
	for !eof {
		select {
		case commitMessage := <-commitChannel:
			if e := commitGit(wt, commitMessage); e != nil {
				logging.LogWarning("[DenyAPI] Reply commit failed: ", e.Error())
			}
		default:
			eof = true
		}
	}
	repository.Push(&git.PushOptions{RemoteName: config.RepoRemote, Auth: gitAuthMethod})
}

func initGitAuth() (transport.AuthMethod, error) {
	if config.RepoSSHKey != "" {
		return ssh.NewPublicKeysFromFile("any", config.RepoSSHKey, config.RepoSSHKeyPass)
	} else {
		return ssh.NewSSHAgentAuth("any")
	}
}

var gitAuthMethod transport.AuthMethod

func runGit(f func(record *DenyRecord) error) error {
	if gitAuthMethod == nil {
		if m, e := initGitAuth(); e == nil {
			gitAuthMethod = m
		} else {
			return e
		}
	}
	if repo, e := git.PlainOpen(config.GitRepoPath); e == nil {
		if wt, e := repo.Worktree(); e == nil {
			defer afterRun(repo) // commit all at the end
			oldRef, _ := repo.Head()
			if e := wt.Pull(&git.PullOptions{RemoteName: config.RepoRemote, Force: true, SingleBranch: true, Auth: gitAuthMethod}); e != nil {
				if e != git.NoErrAlreadyUpToDate {
					return e
				}
			}
			ref, _ := repo.Head()
			if oldRef.Hash() == ref.Hash() {
				return nil // nothing changed
			}
			logging.LogDebug("[DenyAPI] applying ", oldRef.Hash().String(), " => ", ref.Hash().String())
			commitIter, _ := repo.Log(&git.LogOptions{From: ref.Hash()})
			// revert
			commits := make([]*object.Commit, 0)
			for {
				commit, e := commitIter.Next()
				if e != nil || commit.Hash == oldRef.Hash() {
					break
				}
				commits = append(commits, commit)
			}
			for i := len(commits) - 1; i >= 0; i-- {
				if e := checkCommit(commits[i], f); e != nil {
					wt.Reset(&git.ResetOptions{
						Commit: commits[i].ParentHashes[0],
						Mode:   git.HardReset,
					})
					commitLogDebug(commits[i], "resetting to parent because of error: ", e.Error())
					break
				}
			}
		} else {
			return e
		}
	} else {
		return e
	}
	return nil
}

func replyCommit(record *DenyRecord) {
	commitChannel <- fmt.Sprintf("%s was banned until %02d-%02d-%04d %02d:%02d by %s <%s> keyid 0x%16X",
		record.Address.String(),
		record.Expiry.Day(),
		record.Expiry.Month(),
		record.Expiry.Year(),
		record.Expiry.Hour(),
		record.Expiry.Minute(),
		record.Committer.Name,
		record.Committer.Email,
		record.Committer.KeyID,
	)
}
