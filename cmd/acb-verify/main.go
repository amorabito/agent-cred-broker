// Command acb-verify checks act-claim streams offline: signature validity
// against a known public key, plus per-instance sequence gaps and
// duplicates. Events may arrive in any order (Loki queries often return
// newest-first) — sequences are sorted per instance before gap analysis.
// Exit code 1 on any invalid event, 2 on usage errors.
//
// Usage:
//
//	acb-verify -pubkey <base64> [file...]        # or events on stdin
//	logcli query ... | acb-verify -pubkey <base64>
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/amorabito/agent-cred-broker/internal/audit"
)

func main() {
	pubB64 := flag.String("pubkey", "", "base64 Ed25519 public key (from /v1/audit/verify-key or chart values)")
	flag.Parse()
	if *pubB64 == "" {
		fmt.Fprintln(os.Stderr, "acb-verify: -pubkey is required")
		os.Exit(2)
	}
	pub, err := base64.StdEncoding.DecodeString(*pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "acb-verify: invalid public key")
		os.Exit(2)
	}

	readers := []io.Reader{}
	if flag.NArg() == 0 {
		readers = append(readers, os.Stdin)
	}
	for _, path := range flag.Args() {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "acb-verify: %v\n", err)
			os.Exit(2)
		}
		defer f.Close()
		readers = append(readers, f)
	}

	var total, valid, invalid int
	seqs := map[string][]uint64{} // instance -> all seqs seen

	for _, r := range readers {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			total++
			ev, err := audit.Verify(line, ed25519.PublicKey(pub))
			if err != nil {
				invalid++
				fmt.Fprintf(os.Stderr, "INVALID line %d: %v\n", total, err)
				continue
			}
			valid++
			seqs[ev.Broker.Instance] = append(seqs[ev.Broker.Instance], ev.Broker.Seq)
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "acb-verify: read: %v\n", err)
			os.Exit(2)
		}
	}

	// Sort per instance, then report missing seq numbers (deletion evidence
	// within the observed range) and duplicates (possible replay or a
	// reused seq after a broker write failure) separately.
	gaps, dups := 0, 0
	for instance, list := range seqs {
		sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
		for i := 1; i < len(list); i++ {
			switch d := list[i] - list[i-1]; {
			case d == 0:
				dups++
				fmt.Fprintf(os.Stderr, "DUPLICATE SEQ instance=%s seq=%d\n", instance, list[i])
			case d > 1:
				gaps++
				fmt.Fprintf(os.Stderr, "SEQ GAP instance=%s: %d -> %d (%d missing)\n",
					instance, list[i-1], list[i], d-1)
			}
		}
	}

	fmt.Printf("events=%d valid=%d invalid=%d seq_gaps=%d duplicate_seqs=%d instances=%d\n",
		total, valid, invalid, gaps, dups, len(seqs))
	if invalid > 0 {
		os.Exit(1)
	}
}
