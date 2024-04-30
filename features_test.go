package skbtrace

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

type mockBPFTraceProvider struct {
	BPFTraceVersionProvider

	versionStr string
}

func (m mockBPFTraceProvider) Get() ([]byte, error) {
	return []byte(m.versionStr), nil
}

func TestBPFTraceFeatures(t *testing.T) {
	runTest := func(verStr, maskArg string) (mask FeatureFlagMask, err error) {
		spec := FeatureComponentSpec{
			Component: FeatureComponentBPFTrace,
			Provider: mockBPFTraceProvider{
				versionStr: verStr,
			},
		}
		return spec.ProcessFeatures("", maskArg)
	}

	t.Run("oldest", func(t *testing.T) {
		m, err := runTest("bpftrace build-0.9.2", "")
		require.NoError(t, err)
		assert.False(t, m.Supports(FeatureStructKeyword))
	})

	t.Run("newer", func(t *testing.T) {
		m, err := runTest("bpftrace v0.9.4", "")
		require.NoError(t, err)
		assert.True(t, m.Supports(FeatureStructKeyword))
	})

	t.Run("newest", func(t *testing.T) {
		m, err := runTest("bpftrace build-0.18.0-733.230919-dirty", "")
		require.NoError(t, err)
		assert.True(t, m.Supports(FeatureStructKeyword))
	})

	t.Run("mask-override", func(t *testing.T) {
		m, err := runTest("bpftrace build-0.9.2", "struct")
		require.NoError(t, err)
		assert.True(t, m.Supports(FeatureStructKeyword))
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := runTest("2.6.32", "")
		assert.Error(t, err)
	})

	t.Run("mask-invalid", func(t *testing.T) {
		_, err := runTest("bpftrace build-0.9.2", "invalid")
		assert.Error(t, err)
	})
}
