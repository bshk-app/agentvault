package main

import (
	"reflect"
	"testing"
)

func TestParseEnvArgs(t *testing.T) {
	t.Run("defaults + command after --", func(t *testing.T) {
		var o envOptions
		cmd, err := parseEnvArgs([]string{"--", "bun", "dev"}, &o)
		if err != nil {
			t.Fatal(err)
		}
		if o.envFile != ".env" || o.profile != "" || o.noMask {
			t.Errorf("defaults wrong: %+v", o)
		}
		if !reflect.DeepEqual(cmd, []string{"bun", "dev"}) {
			t.Errorf("cmd = %v", cmd)
		}
	})

	t.Run("all flags", func(t *testing.T) {
		var o envOptions
		cmd, err := parseEnvArgs([]string{"--env-file", "x.env", "--profile", "prod", "--no-mask", "--", "node", "s.js"}, &o)
		if err != nil {
			t.Fatal(err)
		}
		if o.envFile != "x.env" || o.profile != "prod" || !o.noMask {
			t.Errorf("flags wrong: %+v", o)
		}
		if !reflect.DeepEqual(cmd, []string{"node", "s.js"}) {
			t.Errorf("cmd = %v", cmd)
		}
	})

	t.Run("no command errors", func(t *testing.T) {
		var o envOptions
		if _, err := parseEnvArgs([]string{"--no-mask"}, &o); err == nil {
			t.Fatal("expected an error when no command is given")
		}
	})
}
