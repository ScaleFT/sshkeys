package sshkeys

import (
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ScaleFT/sshkeys/testdata"
	"github.com/stretchr/testify/require"
)

func testSigners(t *testing.T, name string, a ssh.Signer, b ssh.Signer) {
	require.Equal(t, a.PublicKey().Marshal(), b.PublicKey().Marshal())

	sign := []byte("hello world")
	sig, err := a.Sign(rand.Reader, sign)
	require.NoError(t, err, "signer failed for "+name)

	err = b.PublicKey().Verify(sign, sig)
	require.NoError(t, err, "verify failed for "+name)
}

func TestMarshal(t *testing.T) {
	password := []byte("gopher")
	for _, k := range testdata.PEMEncryptedKeys {
		pk, err := ParseEncryptedRawPrivateKey(k.PEMBytes, []byte(k.EncryptionKey))
		require.NoError(t, err, "error parsing "+k.Name)
		require.NotNil(t, pk, "nil return from parsing "+k.Name)

		signer, err := ssh.NewSignerFromKey(pk)
		require.NoError(t, err)

		data, err := Marshal(pk, &MarshalOptions{
			Passphrase: password,
			Format:     FormatClassicPEM,
		})

		// ed25519 is only specified in the new format
		if k.Name != "ed25519-openssh-encrypted" {
			require.NoError(t, err)
			require.NotNil(t, data, "nil return from marshaling "+k.Name)

			pk2, err := ParseEncryptedRawPrivateKey(data, password)
			require.NoError(t, err, "error from parsing "+k.Name)
			require.NotNil(t, pk2, "nil return from parsing "+k.Name)

			signer2, err := ssh.NewSignerFromKey(pk2)
			require.NoError(t, err)

			testSigners(t, k.Name, signer, signer2)
		}

		// now use new format
		data, err = Marshal(pk, &MarshalOptions{
			Passphrase: password,
			Format:     FormatOpenSSHv1,
		})
		if err != nil && err.Error() == "sshkeys: unsupported key type *dsa.PrivateKey" {
			continue
		}
		require.NoError(t, err)
		require.NotNil(t, data, "nil return from marshaling "+k.Name)

		//		println("input: " + string(data))
		pk3, err := ParseEncryptedRawPrivateKey(data, password)
		require.NoError(t, err, "error from parsing "+k.Name)
		require.NotNil(t, pk3, "nil return from parsing "+k.Name)

		signer3, err := ssh.NewSignerFromKey(pk3)
		require.NoError(t, err)

		testSigners(t, k.Name, signer, signer3)
	}
}
