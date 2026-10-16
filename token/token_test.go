package token

import (
	"path/filepath"
	"testing"
	"time"
)

func TestToken(t *testing.T) {
	SetStatefulFilename(filepath.Join(t.TempDir(), "test.jsonl"))

	future := time.Now().Add(time.Hour)
	user := "user"
	_, err := Update(&Stateful{
		Token:       "token",
		Group:       "group",
		Username:    &user,
		Permissions: []string{"present"},
		Expires:     &future,
	}, "")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	token, err := Parse("token", nil)
	if err != nil || token == nil {
		t.Fatalf("Parse: %v", err)
	}

	_, _, err = token.Check("galene.org:8443", "group")
	if err != nil {
		t.Errorf("Check: %v", err)
	}

	token, err = Parse("bad", nil)
	if err == nil {
		t.Errorf("Expected error, got %v", token)
	}

	token, err = Parse("bad", []map[string]interface{}{})
	if err == nil {
		t.Errorf("Expected error, got %v", token)
	}
}
