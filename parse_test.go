package sshkeys

import (
	"testing"

	"github.com/ScaleFT/sshkeys/testdata"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	for name, k := range testdata.PEMBytes {
		pk, err := ParseEncryptedPrivateKey(k, nil)
		require.NoError(t, err, "error parsing "+name)
		require.NotNil(t, pk, "nil return from parsing "+name)
	}
}

func TestEncryptedParse(t *testing.T) {
	wrongKey := []byte("hello world")
	for _, k := range testdata.PEMEncryptedKeys {
		pk, err := ParseEncryptedPrivateKey(k.PEMBytes, wrongKey)
		require.Error(t, err, "expected error from "+k.Name)
		require.Equal(t, err, IncorrectPasswordError, "expected error from "+k.Name)
		require.Nil(t, pk, "non-nil return from parsing "+k.Name)

		pk, err = ParseEncryptedPrivateKey(k.PEMBytes, []byte(k.EncryptionKey))
		require.NoError(t, err)
		require.NotNil(t, pk, "nil return from parsing "+k.Name)
	}
}
