package sshkeys

import (
	"testing"

	"github.com/ScaleFT/sshkeys/testdata"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	for _, k := range testdata.PEMBytes {
		t.Run(k.Name, func(t *testing.T) {
			pk, err := ParseEncryptedPrivateKey(k.PEMBytes, nil)
			require.NoError(t, err, "error parsing "+k.Name)
			require.NotNil(t, pk, "nil return from parsing "+k.Name)
		})
	}
}

func TestEncryptedParse(t *testing.T) {
	wrongKey := []byte("hello world")
	for _, k := range testdata.PEMEncryptedKeys {
		t.Run(k.Name, func(t *testing.T) {
			pk, err := ParseEncryptedPrivateKey(k.PEMBytes, wrongKey)
			require.Error(t, err, "expected error from "+k.Name)
			require.Equal(t, err, ErrIncorrectPassword, "expected error from "+k.Name)
			require.Nil(t, pk, "non-nil return from parsing "+k.Name)

			pk, err = ParseEncryptedPrivateKey(k.PEMBytes, []byte(k.EncryptionKey))
			require.NoError(t, err)
			require.NotNil(t, pk, "nil return from parsing "+k.Name)
		})
	}
}
