// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls      []fakeCall
	tableFound bool
}

type fakeCall struct {
	args  []string
	stdin string
}

func (r *fakeRunner) Run(_ context.Context, args []string, stdin string) ([]byte, error) {
	r.calls = append(r.calls, fakeCall{args: append([]string(nil), args...), stdin: stdin})
	switch strings.Join(args, " ") {
	case "list table inet cilium_noebpf":
		if r.tableFound {
			return []byte("table inet cilium_noebpf {}"), nil
		}
		return []byte("Error: No such file or directory"), errors.New("exit status 1")
	case "delete table inet cilium_noebpf":
		return nil, nil
	case "-f -":
		return nil, nil
	default:
		return []byte("unexpected"), errors.New("unexpected command")
	}
}

func TestApplyCreatesTableWhenMissing(t *testing.T) {
	runner := &fakeRunner{}
	if err := Apply(context.Background(), runner, oneServiceState()); err != nil {
		t.Fatal(err)
	}
	got := callArgs(runner.calls)
	want := [][]string{{"list", "table", "inet", "cilium_noebpf"}, {"-f", "-"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected calls: got %#v want %#v", got, want)
	}
	if !strings.Contains(runner.calls[1].stdin, "table inet cilium_noebpf") {
		t.Fatalf("apply call missing rendered table: %q", runner.calls[1].stdin)
	}
}

func TestApplyDeletesExistingTableFirst(t *testing.T) {
	runner := &fakeRunner{tableFound: true}
	if err := Apply(context.Background(), runner, oneServiceState()); err != nil {
		t.Fatal(err)
	}
	got := callArgs(runner.calls)
	want := [][]string{{"list", "table", "inet", "cilium_noebpf"}, {"-f", "-"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected calls: got %#v want %#v", got, want)
	}
	if !strings.HasPrefix(runner.calls[1].stdin, "delete table inet cilium_noebpf\n") {
		t.Fatalf("existing-table replacement must be one nft transaction, got:\n%s", runner.calls[1].stdin)
	}
}

func callArgs(calls []fakeCall) [][]string {
	out := make([][]string, 0, len(calls))
	for _, call := range calls {
		out = append(out, call.args)
	}
	return out
}

func oneServiceState() DesiredState {
	return DesiredState{Services: []ServiceDNAT{{
		FrontendAddr: netip.MustParseAddr("10.245.0.10"),
		FrontendPort: 80,
		Protocol:     ProtocolTCP,
		BackendAddr:  netip.MustParseAddr("10.244.1.20"),
		BackendPort:  80,
	}}}
}
