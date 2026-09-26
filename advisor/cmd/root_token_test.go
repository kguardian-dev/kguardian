package cmd

import (
	"errors"
	"testing"
)

func TestResolveBrokerToken(t *testing.T) {
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	files := map[string]string{"/tok": "  file-token\n", "/empty": "\n"}
	readFile := func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("no such file")
	}

	if got, err := resolveBrokerToken("", getenv, readFile); err != nil || got != "" {
		t.Fatalf("no config: got %q, %v; want empty", got, err)
	}

	env["BROKER_AUTH_TOKEN"] = "legacy"
	if got, _ := resolveBrokerToken("", getenv, readFile); got != "legacy" {
		t.Errorf("BROKER_AUTH_TOKEN fallback: got %q", got)
	}

	env["KGUARDIAN_BROKER_TOKEN"] = " preferred "
	if got, _ := resolveBrokerToken("", getenv, readFile); got != "preferred" {
		t.Errorf("KGUARDIAN_BROKER_TOKEN must win over BROKER_AUTH_TOKEN: got %q", got)
	}

	if got, _ := resolveBrokerToken("/tok", getenv, readFile); got != "file-token" {
		t.Errorf("--broker-token-file must win over env: got %q", got)
	}

	if _, err := resolveBrokerToken("/empty", getenv, readFile); err == nil {
		t.Error("an empty token file must be an error, not a silent no-auth")
	}
	if _, err := resolveBrokerToken("/missing", getenv, readFile); err == nil {
		t.Error("a missing token file must be an error")
	}
}
