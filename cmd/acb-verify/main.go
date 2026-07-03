// Command acb-verify checks act-claim streams offline: signature validity
// against a known public key, and per-instance sequence gaps. Exit code 1 on
// any invalid event, 2 on usage errors.
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
)

import "github.com/amorabito/agent-cred-broker/internal/audit"

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
	lastSeq := map[string]uint64{} // instance -> last seq seen
	gaps := 0

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
			if last, ok := lastSeq[ev.Broker.Instance]; ok && ev.Broker.Seq != last+1 {
				gaps++
				fmt.Fprintf(os.Stderr, "SEQ GAP instance=%s: %d -> %d\n", ev.Broker.Instance, last, ev.Broker.Seq)
			}
			lastSeq[ev.Broker.Instance] = ev.Broker.Seq
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "acb-verify: read: %v\n", err)
			os.Exit(2)
		}
	}

	fmt.Printf("events=%d valid=%d invalid=%d seq_gaps=%d instances=%d\n",
		total, valid, invalid, gaps, len(lastSeq))
	if invalid > 0 {
		os.Exit(1)
	}
}
