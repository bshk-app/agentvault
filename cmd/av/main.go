// Command av is the thin AgentVault CLI.
package main

import (
	"fmt"
	"os"

	"github.com/beshkenadze/agentvault/internal/client"
	"github.com/beshkenadze/agentvault/internal/transport"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "ping":
		runPing()
	case "run":
		runRun(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  av ping\n  av run [--profile P] -- cmd args...")
}

func runPing() {
	path, err := transport.DefaultSocketPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(1)
	}
	out, err := client.New(path).Ping()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

// runRun parses `av run [--profile P] [--] cmd args...` and executes the child
// with resolved secrets injected and its output masked at the source (layer 1).
// Exit-code mapping for locked/denied is refined in P4.7; for now a resolve error
// prints to stderr and exits 1.
func runRun(args []string) {
	profile := "smoke" // default profile; override with --profile
	cmdArgs, err := parseRunArgs(args, &profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		usage()
		os.Exit(2)
	}

	path, err := transport.DefaultSocketPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(1)
	}
	code, err := client.Run(client.New(path), client.RunOptions{
		Profile: profile,
		Command: cmdArgs,
	}, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "av:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// parseRunArgs extracts --profile and the child argv (everything after `--`, or
// the first non-flag token onward). It sets *profile and returns the child argv.
func parseRunArgs(args []string, profile *string) ([]string, error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return args[i+1:], nil
		case a == "--profile":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--profile needs a value")
			}
			*profile = args[i+1]
			i++
		case len(a) > 10 && a[:10] == "--profile=":
			*profile = a[10:]
		default:
			// First non-flag token begins the child argv.
			return args[i:], nil
		}
	}
	return nil, fmt.Errorf("no command given")
}
