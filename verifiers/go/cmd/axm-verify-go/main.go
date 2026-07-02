// axm-verify-go — independent Go verifier for AXM Genesis v1 shards.
//
// Frozen CLI contract (spec 13.1, 13.4; COMPATIBILITY.md section 4):
//
//	axm-verify-go shard <shard_dir> --trusted-key <publisher_pubkey>
//
// stdout: single-line machine-readable JSON result.
// stderr: one "CODE: message" line per error.
// exit:   0 PASS; 2 FAIL where every error code is structural
//
//	({E_LAYOUT_MISSING, E_SCHEMA_MISSING, E_SIG_MISSING}) or the path
//	is missing, and for command-line usage errors; 1 any other FAIL.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/BigBirdReturns/axm-genesis/verifiers/go/internal/axm"
)

const usage = "usage: axm-verify-go shard <shard_dir> --trusted-key <publisher_pubkey>"

func main() {
	args := os.Args[1:]
	if len(args) < 1 || args[0] != "shard" {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	var shardPath, keyPath string
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--trusted-key":
			if i+1 >= len(rest) {
				fmt.Fprintln(os.Stderr, usage)
				os.Exit(2)
			}
			i++
			keyPath = rest[i]
		case strings.HasPrefix(a, "--trusted-key="):
			keyPath = strings.TrimPrefix(a, "--trusted-key=")
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(os.Stderr, "unknown option %q\n%s\n", a, usage)
			os.Exit(2)
		case shardPath == "":
			shardPath = a
		default:
			fmt.Fprintf(os.Stderr, "unexpected argument %q\n%s\n", a, usage)
			os.Exit(2)
		}
	}
	if shardPath == "" || keyPath == "" {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	trustedKey, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read trusted key %q: %v\n", keyPath, err)
		os.Exit(2)
	}

	result := axm.Verify(shardPath, trustedKey)

	out, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "internal error: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(out))
	for _, e := range result.Errors {
		fmt.Fprintf(os.Stderr, "%s: %s\n", e.Code, e.Message)
	}
	os.Exit(result.ExitCode())
}
