package clitesting

import (
	"testing"
)

func TestDumpTest(t *testing.T) {
	for _, args := range [][]string{
		// Simple test
		{"dump", "-P", "xmit", "-o", "ip"},

		// Simple test, but with filter alias
		{"dump", "-P", "recv", "-o", "ip", "-F", "src == 127.0.0.1"},

		// Test some objectless outputs
		{"dump", "-P", "k:__skb_checksum", "-o", "task", "-o", "__skb_checksum", "-F", "len > 1000"},

		// Inner TCP test
		{"dump", "-P", "recv", "-o", "inner-tcp", "-F", "tcp-flags == S"},

		// Inner IPv6/UDP test
		{"dump", "-P", "recv", "-o", "inner-udp", "-6", "-F", "inner-dport == 53"},

		// Interface filter test
		{"dump", "-P", "recv", "-o", "ip", "-i", "eth3"},

		// Test context probes
		{"dump", "-C", "recv", "--context-filter", `dev == "eth0"`,
			"-P", "xmit", "-F", `dev == "eth1"`, "-o", "ip"},
	} {
		RunCommandTest(t, args)
	}
}

func TestAggrTest(t *testing.T) {
	for _, args := range [][]string{
		// Simple test
		{"aggr", "-P", "xmit", "-k", "src,dst"},

		// Test with custom function
		{"aggr", "-P", "recv", "-k", "src", "-f", "min", "-a", "$iph->ttl"},

		// Inner IPv6 aggregate test
		{"aggr", "-6", "-P", "xmit", "-k", "outer-dst", "-F", "inner-src == fc00::1"},
	} {
		RunCommandTest(t, args)
	}
}

func TestErrorTest(t *testing.T) {
	for _, args := range [][]string{
		{"dump", "-P", "unknown_probe"},

		{"dump", "-P", "recv", "-F", "src ======= 127.0.0.1"},

		{"dump", "-P", "recv", "-F", "src == a.b.c.d"},
	} {
		RunCommandTest(t, args)
	}
}
