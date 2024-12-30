// xor.go
package crypto

type Cipher struct {
	key []byte
}

func NewCipher(key []byte) *Cipher {
	if key == nil {
		key = []byte("goleveldb-key")
	}
	return &Cipher{key: key}
}

func (c *Cipher) EncryptAt(data []byte, offset int64) []byte {
	result := make([]byte, len(data))
	keyLen := int64(len(c.key))

	keyOffset := offset % keyLen

	for i := 0; i < len(data); i++ {
		keyIndex := (keyOffset + int64(i)) % keyLen
		result[i] = data[i] ^ c.key[keyIndex]
	}
	return result
}

func (c *Cipher) DecryptAt(data []byte, offset int64) []byte {
	return c.EncryptAt(data, offset)
}

func (c *Cipher) Encrypt(data []byte) []byte {
	return c.EncryptAt(data, 0)
}

func (c *Cipher) Decrypt(data []byte) []byte {
	return c.DecryptAt(data, 0)
}
