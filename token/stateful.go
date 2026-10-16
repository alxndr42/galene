package token

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jech/galene/config"
)

var ErrTagMismatch = errors.New("tag mismatch")

// A stateful token
type Stateful struct {
	Token            string     `json:"token"`
	Group            string     `json:"group"`
	IncludeSubgroups bool       `json:"includeSubgroups,omitempty"`
	Username         *string    `json:"username,omitempty"`
	Permissions      []string   `json:"permissions"`
	Expires          *time.Time `json:"expires,omitempty"`
	NotBefore        *time.Time `json:"not-before,omitempty"`
	IssuedAt         *time.Time `json:"issuedAt,omitempty"`
	IssuedBy         *string    `json:"issuedBy,omitempty"`
}

func (token *Stateful) Clone() *Stateful {
	return &Stateful{
		Token:            token.Token,
		Group:            token.Group,
		IncludeSubgroups: token.IncludeSubgroups,
		Username:         token.Username,
		Permissions:      append([]string(nil), token.Permissions...),
		Expires:          token.Expires,
		NotBefore:        token.NotBefore,
		IssuedAt:         token.IssuedAt,
		IssuedBy:         token.IssuedBy,
	}
}

// A set of stateful tokens, kept in sync with a JSONL representation in
// a file.  The synchronisation is slightly racy, so both reading and
// modifying tokens are protected by a mutex.
type state struct {
	filename   string
	mu         sync.Mutex
	configFile config.ConfigFile
	configTag  string
	tokens     map[string]*Stateful
}

var tokens state

func SetStatefulFilename(filename string) {
	tokens.mu.Lock()
	defer tokens.mu.Unlock()
	tokens.filename = filename
	tokens.configFile = config.NewConfigFile(filename)
	tokens.configTag = ""
	tokens.tokens = nil
}

func (state *state) Get(token string) (*Stateful, string, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.load(); err != nil {
		return nil, "", err
	}
	if state.tokens == nil {
		return nil, "", os.ErrNotExist
	}
	t := state.tokens[token]
	if t == nil {
		return nil, "", os.ErrNotExist
	}
	return t, state.configTag, nil
}

// Get fetches a stateful token.
// It returns os.ErrNotExist if the token doesn't exist.
func Get(token string) (*Stateful, string, error) {
	return tokens.Get(token)
}

func (token *Stateful) match(group string) bool {
	if group == "" {
		return token.IncludeSubgroups && token.Group == ""
	}
	if group == token.Group {
		return true
	}
	if token.IncludeSubgroups {
		if token.Group == "" {
			return true
		}
		return strings.HasPrefix(group, token.Group+"/")
	}
	return false
}

func (token *Stateful) Check(host, group string) (string, []string, error) {
	if !token.match(group) {
		return "", nil, errors.New("token for bad group")
	}
	now := time.Now()
	if token.Expires == nil || now.After(*token.Expires) {
		return "", nil, errors.New("token has expired")
	}
	if token.NotBefore != nil && now.Before(*token.NotBefore) {
		return "", nil, errors.New("token is in the future")
	}

	// the username from the token overrides the one from the client.
	user := ""
	if token.Username != nil {
		user = *token.Username
	}

	return user, token.Permissions, nil
}
func (token *Stateful) NeedsUsername() bool {
	return token.Username == nil
}


// called locked
func (state *state) reset() {
	state.configTag = ""
	state.tokens = nil
}

// load updates the state from the corresponding file.
// called locked
func (state *state) load() error {
	currentTag := state.configFile.Tag()
	if currentTag != state.configTag {
		err := state.configFile.Read(func(r io.Reader) error {
			if r == nil {
				state.reset()
				return nil
			}

			ts := make(map[string]*Stateful)
			decoder := json.NewDecoder(r)
			for {
				var t Stateful
				err := decoder.Decode(&t)
				if err == io.EOF {
					break
				} else if err != nil {
					state.reset()
					return err
				}
				ts[t.Token] = &t
			}
			state.tokens = ts
			return nil
		})
		if err != nil {
			return err
		}

		state.configTag = currentTag
	}
	return nil
}

// Update adds or updates a token.
// If etag is the empty string, it is added if it didn't exist.  If etag
// is not empty, it is added if it matches the state's etag.
func (state *state) Update(token *Stateful, etag string) (*Stateful, error) {
	tokens.mu.Lock()
	defer tokens.mu.Unlock()

	if state.filename == "" {
		if etag != "" {
			return nil, ErrTagMismatch
		}
		return nil, os.ErrNotExist
	}

	if err := state.load(); err != nil {
		return nil, err
	}

	if state.tokens == nil {
		state.tokens = make(map[string]*Stateful)
	}

	old, ok := state.tokens[token.Token]
	if ok {
		if etag != state.configTag {
			return nil, ErrTagMismatch
		}
		state.tokens[token.Token] = token
		if err := state.rewrite(); err != nil {
			state.tokens[token.Token] = old
			return nil, err
		}
		return token, nil
	}

	if etag != "" {
		return nil, ErrTagMismatch
	}
	return state.add(token)
}

func Delete(token string, etag string) error {
	return tokens.Delete(token, etag)
}

func (state *state) Delete(token string, etag string) error {
	tokens.mu.Lock()
	defer tokens.mu.Unlock()

	if state.filename == "" {
		return os.ErrNotExist
	}

	if err := state.load(); err != nil {
		return err
	}

	if state.tokens == nil {
		return os.ErrNotExist
	}

	old, ok := state.tokens[token]
	if !ok {
		return os.ErrNotExist
	}
	if etag != state.configTag {
		return ErrTagMismatch
	}
	delete(state.tokens, token)
	if err := state.rewrite(); err != nil {
		state.tokens[token] = old
		return err
	}
	return nil
}

// add unconditionally adds a token, which is assumed to not exist.
// called locked
func (state *state) add(token *Stateful) (*Stateful, error) {
	err := state.configFile.Append(state.configTag, func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		return encoder.Encode(token)
	})
	if err != nil {
		return nil, err
	}
	state.configTag = state.configFile.Tag()

	if state.tokens == nil {
		state.tokens = make(map[string]*Stateful)
	}
	state.tokens[token.Token] = token.Clone()

	return token, nil
}

func Update(token *Stateful, etag string) (*Stateful, error) {
	return tokens.Update(token, etag)
}

// called locked
func (state *state) rewrite() error {
	if state.tokens == nil || len(state.tokens) == 0 {
		return state.configFile.Delete(state.configTag)
	}

	err := state.configFile.Write(state.configTag, func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		for _, t := range state.tokens {
			err := encoder.Encode(t)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil
	}
	state.configTag = state.configFile.Tag()
	return nil
}

// called locked
func (state *state) list(group string, all bool) ([]*Stateful, string, error) {
	if group != "" && all {
		return nil, "", errors.New("cannot specify both group and all")
	}
	if err := state.load(); err != nil {
		return nil, "", err
	}

	a := make([]*Stateful, 0)
	if state.tokens == nil {
		return a, state.configTag, nil
	}
	for _, t := range state.tokens {
		if !all && t.Group != group {
			continue
		}
		a = append(a, t)
	}
	sort.Slice(a, func(i, j int) bool {
		if a[j].Expires == nil {
			return false
		}
		if a[i].Expires == nil {
			return true
		}
		return (*a[i].Expires).Before(*a[j].Expires)
	})
	return a, state.configTag, nil
}

func (state *state) List(group string) ([]*Stateful, string, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.list(group, false)
}

func List(group string) ([]*Stateful, string, error) {
	return tokens.List(group)
}

func (state *state) Expire() error {
	state.mu.Lock()
	defer state.mu.Unlock()

	if err := state.load(); err != nil {
		return err
	}

	now := time.Now()
	cutoff := now.Add(-time.Hour * 24 * 7)

	modified := false
	for k, t := range state.tokens {
		if t.Expires != nil && t.Expires.Before(cutoff) {
			delete(state.tokens, k)
			modified = true
		}
	}

	if modified {
		err := state.rewrite()
		if err != nil {
			return err
		}
	}
	return nil
}

func Expire() error {
	return tokens.Expire()
}
