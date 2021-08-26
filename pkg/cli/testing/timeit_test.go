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
		{"timeit", "forward", "--ingress", "-i", "tapxx-1", "-p", "tcp"},

		// TCP test
		{"timeit", "tcp", "handshake", "--ingress", "-i", "tapxx-1"},
	} {
		RunCommandTest(t, args)
	}
}
