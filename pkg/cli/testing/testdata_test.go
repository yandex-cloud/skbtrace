package clitesting

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDataTest(t *testing.T) {
	paths, err := filepath.Glob("testdata/*")
	assert.NoError(t, err)

	for _, path := range paths {
		fname := filepath.Base(path)
		if len(fname) > maxFileNameLen {
			t.Errorf("Test data file '%s' exceeds limit of %d characters, it might break eCryptFS",
				fname, maxFileNameLen)
		}

		if strings.ContainsAny(fname, ":") {
			t.Errorf("Test data file '%s' has punctuation symbols, might break go-get", fname)
		}
	}
}
