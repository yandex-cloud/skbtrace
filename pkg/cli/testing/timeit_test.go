package clitesting

import (
	"testing"
)

func TestTimeTest(t *testing.T) {
	for _, args := range [][]string{
		// Explicit from/to test
		{"timeit",
			"from", "-P", "recv", "-k", "src,dst",
			"to", "-P", "xmit", "aggr", "5s"},

		// Errorneous from/to test
		{"timeit", "from", "-k", "src,dst", "to", "aggr", "5s"},

		// Forwarding test
		{"timeit", "forward", "--inbound", "-i", "tapxx-1", "-p", "tcp"},

		// TCP test
		{"timeit", "tcp", "handshake", "--inbound", "-i", "tapxx-1"},
		{"timeit", "tcp", "lifetime", "--outbound"},
	} {
		RunCommandTest(t, args)
	}
}
