package mi

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

type PublicKey struct {
	*rsa.PublicKey
}

type PrivateKey struct {
	*rsa.PrivateKey
}

func (r *PrivateKey) Decrypt(ciphertext []byte) ([]byte, error) {
	out := make([]byte, 0, 1024)
	for len(ciphertext) > 0 {
		chunkSize := 256
		if chunkSize > len(ciphertext) {
			chunkSize = len(ciphertext)
		}
		chunk := ciphertext[:chunkSize]
		ciphertext = ciphertext[chunkSize:]
		b, err := rsa.DecryptPKCS1v15(rand.Reader, r.PrivateKey, chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

func (r *PublicKey) Verify(msg []byte, sig []byte) error {
	h := sha256.New()
	h.Write(msg)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, sig)
}
