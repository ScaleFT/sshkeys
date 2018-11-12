package sshkeys_test

import (
	"crypto/rand"
	"testing"

	"github.com/ScaleFT/sshkeys"
	"github.com/ScaleFT/sshkeys/testdata"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func testSigners(t *testing.T, name string, a ssh.Signer, b ssh.Signer) {
	require.Equal(t, a.PublicKey().Marshal(), b.PublicKey().Marshal())

	sign := []byte("hello world")
	sig, err := a.Sign(rand.Reader, sign)
	require.NoError(t, err, "signer failed for %s", name)

	err = b.PublicKey().Verify(sign, sig)
	require.NoError(t, err, "verify failed for %s", name)
}

func TestMarshalOldFormat(t *testing.T) {
	password := []byte("gopher")
	for _, k := range testdata.PEMEncryptedKeys {
		// ed25519 is only specified in the new format
		if k.Name == "ed25519-openssh-encrypted-aes256-cbc" || k.Name == "ed25519-openssh-encrypted-aes256-ctr" {
			continue
		}
		t.Run(k.Name, func(t *testing.T) {
			pk, err := sshkeys.ParseEncryptedRawPrivateKey(k.PEMBytes, []byte(k.EncryptionKey))
			require.NoError(t, err, "error parsing %s", k.Name)
			require.NotNil(t, pk, "nil return from parsing %s", k.Name)

			signer, err := ssh.NewSignerFromKey(pk)
			require.NoError(t, err)

			data, err := sshkeys.Marshal(pk, &sshkeys.MarshalOptions{
				Passphrase: password,
				Format:     sshkeys.FormatClassicPEM,
			})

			require.NoError(t, err)
			require.NotNil(t, data, "nil return from marshaling %s", k.Name)

			pk2, err := sshkeys.ParseEncryptedRawPrivateKey(data, password)
			require.NoError(t, err, "error from parsing %s", k.Name)
			require.NotNil(t, pk2, "nil return from parsing %s", k.Name)

			signer2, err := ssh.NewSignerFromKey(pk2)
			require.NoError(t, err)

			testSigners(t, k.Name, signer, signer2)
		})
	}
}

func TestMarshalNewFormat(t *testing.T) {
	password := []byte("gopher")
	for _, k := range testdata.PEMEncryptedKeys {
		if k.Name == "dsa-encrypted-aes256-cbc" {
			continue
		}

		t.Run(k.Name, func(t *testing.T) {
			pk, err := sshkeys.ParseEncryptedRawPrivateKey(k.PEMBytes, []byte(k.EncryptionKey))
			require.NoError(t, err, "error parsing %s", k.Name)
			require.NotNil(t, pk, "nil return from parsing %s", k.Name)

			signer, err := ssh.NewSignerFromKey(pk)
			require.NoError(t, err)

			data, err := sshkeys.Marshal(pk, &sshkeys.MarshalOptions{
				Passphrase: password,
				Format:     sshkeys.FormatOpenSSHv1,
			})

			require.NoError(t, err)
			require.NotNil(t, data, "nil return from marshaling %s", k.Name)

			pk2, err := sshkeys.ParseEncryptedRawPrivateKey(data, password)
			require.NoError(t, err, "error from parsing %s", k.Name)
			require.NotNil(t, pk2, "nil return from parsing %s", k.Name)

			signer2, err := ssh.NewSignerFromKey(pk2)
			require.NoError(t, err)

			testSigners(t, k.Name, signer, signer2)
		})
	}
}
