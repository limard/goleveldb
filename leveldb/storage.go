package leveldb

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"sync/atomic"

	"github.com/syndtr/goleveldb/leveldb/storage"
)

var (
	EncryptionVersion int // 0 NONE, 1 XOR, 2 AES
	EncryptionKey     []byte
)

type iStorage struct {
	storage.Storage
	read  uint64
	write uint64
}

func (c *iStorage) Open(fd storage.FileDesc) (storage.Reader, error) {
	r, err := c.Storage.Open(fd)
	cipher := newCipher(EncryptionKey)
	return &iStorageReader{r, c, cipher, 0, fd}, err
}

func (c *iStorage) Create(fd storage.FileDesc) (storage.Writer, error) {
	w, err := c.Storage.Create(fd)
	cipher := newCipher(EncryptionKey)
	return &iStorageWriter{w, c, cipher, 0, fd}, err
}

func (c *iStorage) reads() uint64 {
	return atomic.LoadUint64(&c.read)
}

func (c *iStorage) writes() uint64 {
	return atomic.LoadUint64(&c.write)
}

// newIStorage returns the given storage wrapped by iStorage.
func newIStorage(s storage.Storage) *iStorage {
	return &iStorage{s, 0, 0}
}

type iStorageReader struct {
	storage.Reader
	c      *iStorage
	cipher iCipher
	offset int64
	fd     storage.FileDesc // 文件描述符
}

// var Debug = log.New(os.Stdout, "[Storage Debug] ", log.Lshortfile)

func (r *iStorageReader) Read(p []byte) (n int, err error) {
	currentOffset := r.offset
	n, err = r.Reader.Read(p)
	if n > 0 && r.cipher != nil {
		// Debug.Printf("Reading: fd={Type:%d, Num:%d}, offset=%d, size=%d, totalRead=%d",
		// 	r.fd.Type, r.fd.Num, currentOffset, n, atomic.LoadUint64(&r.c.read))
		decrypted := r.cipher.DecryptAt(p[:n], currentOffset)
		copy(p, decrypted)
		r.offset = currentOffset + int64(n)
		atomic.AddUint64(&r.c.read, uint64(n))
	}
	if err != nil {
		// Debug.Printf("Read error at offset %d: %v", currentOffset, err)
	}
	return n, err
}

func (r *iStorageReader) ReadAt(p []byte, off int64) (n int, err error) {
	n, err = r.Reader.ReadAt(p, off)
	if n > 0 && r.cipher != nil {
		// Debug.Printf("ReadingAt: fd={Type:%d, Num:%d}, offset=%d, size=%d",
		// 	r.fd.Type, r.fd.Num, off, n)
		decrypted := r.cipher.DecryptAt(p[:n], off)
		copy(p, decrypted)
		atomic.AddUint64(&r.c.read, uint64(n))
	}
	if err != nil {
		// Debug.Printf("ReadAt error: %v", err)
	}
	return n, err
}

type iStorageWriter struct {
	storage.Writer
	c      *iStorage
	cipher iCipher
	offset int64
	fd     storage.FileDesc // 文件描述符
}

func (w *iStorageWriter) Write(p []byte) (n int, err error) {
	if w.cipher != nil {
		// Debug.Printf("Writing: fd={Type:%d, Num:%d}, offset=%d, size=%d",
		// 	w.fd.Type, w.fd.Num, w.offset, len(p))
		encrypted := w.cipher.EncryptAt(p, w.offset)
		n, err = w.Writer.Write(encrypted)
		if err != nil {
			// Debug.Printf("Write error: %v", err)
			return
		}
		w.offset += int64(n)
	} else {
		n, err = w.Writer.Write(p)
		if err != nil {
			return
		}
		w.offset += int64(n)
	}
	atomic.AddUint64(&w.c.write, uint64(n))
	return n, err
}

type iCipher interface {
	EncryptAt(data []byte, offset int64) []byte
	DecryptAt(data []byte, offset int64) []byte
	Encrypt(data []byte) []byte
	Decrypt(data []byte) []byte
}

func newCipher(key []byte) iCipher {
	if key == nil {
		return nil
	}
	switch EncryptionVersion {
	case 1:
		return &xorCipher{key: key}
	case 2:
		return newAESCipher(key)
	default:
		return nil
	}
}

// xorCipher implements XOR encryption

const BlockSize = 40

type xorCipher struct {
	key []byte
}

func (c *xorCipher) EncryptAt(data []byte, offset int64) []byte {
	result := make([]byte, len(data))
	keyLen := int64(len(c.key))

	// Include file type and number in offset calculation
	keyOffset := offset % keyLen

	for i := 0; i < len(data); i++ {
		keyIndex := (keyOffset + int64(i)) % keyLen
		result[i] = data[i] ^ c.key[keyIndex]
	}
	return result
}

func (c *xorCipher) DecryptAt(data []byte, offset int64) []byte {
	return c.EncryptAt(data, offset)
}

func (c *xorCipher) Encrypt(data []byte) []byte {
	return c.EncryptAt(data, 0)
}

func (c *xorCipher) Decrypt(data []byte) []byte {
	return c.DecryptAt(data, 0)
}

// aesCipher implements AES encryption

type aesCipher struct {
	key   []byte
	block cipher.Block
}

func newAESCipher(key []byte) *aesCipher {
	// Ensure key is exactly 32 bytes for AES-256
	if len(key) < 32 {
		newKey := make([]byte, 32)
		copy(newKey, key)
		for i := len(key); i < 32; i++ {
			newKey[i] = byte(i)
		}
		key = newKey
	} else if len(key) > 32 {
		key = key[:32]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	return &aesCipher{
		key:   key,
		block: block,
	}
}

func (c *aesCipher) getIV(offset int64) []byte {
	// Calculate block start offset
	blockStart := (offset / BlockSize) * BlockSize

	// Create IV based on block start
	iv := make([]byte, aes.BlockSize)
	copy(iv[:8], c.key[:8])
	binary.LittleEndian.PutUint64(iv[8:16], uint64(blockStart))

	// Debug.Printf("AES IV for offset %d: block_start=%d, iv=%x",
	// 	offset, blockStart, iv)

	return iv
}

func (c *aesCipher) EncryptAt(data []byte, offset int64) []byte {
	if len(data) == 0 {
		return data
	}

	// Create the result buffer
	result := make([]byte, len(data))

	// Calculate the block start offset
	blockStart := (offset / BlockSize) * BlockSize
	offsetInBlock := offset - blockStart

	// If the data starts in the middle of a block and ends in the same block
	if offsetInBlock+int64(len(data)) <= BlockSize {
		// Get IV for this block
		iv := c.getIV(blockStart)
		stream := cipher.NewCTR(c.block, iv)

		// Skip to the correct position in the block
		if offsetInBlock > 0 {
			temp := make([]byte, offsetInBlock)
			stream.XORKeyStream(temp, temp) // Advance the stream
		}

		// Encrypt the data
		stream.XORKeyStream(result, data)
		return result
	}

	// Handle data that spans multiple blocks
	var processed int64
	currentOffset := offset

	// Handle the first partial block
	if offsetInBlock > 0 {
		bytesInFirstBlock := BlockSize - int(offsetInBlock)
		iv := c.getIV(blockStart)
		stream := cipher.NewCTR(c.block, iv)

		// Skip to the correct position
		temp := make([]byte, offsetInBlock)
		stream.XORKeyStream(temp, temp)

		// Encrypt the remainder of the first block
		stream.XORKeyStream(result[:bytesInFirstBlock], data[:bytesInFirstBlock])
		processed = int64(bytesInFirstBlock)
		currentOffset += int64(bytesInFirstBlock)
	}

	// Handle full blocks
	for processed < int64(len(data)) {
		blockStart = (currentOffset / BlockSize) * BlockSize
		remainingBytes := int64(len(data)) - processed
		bytesInBlock := BlockSize
		if remainingBytes < int64(BlockSize) {
			bytesInBlock = int(remainingBytes)
		}

		iv := c.getIV(blockStart)
		stream := cipher.NewCTR(c.block, iv)
		stream.XORKeyStream(result[processed:processed+int64(bytesInBlock)],
			data[processed:processed+int64(bytesInBlock)])

		processed += int64(bytesInBlock)
		currentOffset += int64(bytesInBlock)
	}

	return result
}

func (c *aesCipher) DecryptAt(data []byte, offset int64) []byte {
	// AES CTR mode is symmetric, so we can use the same function
	return c.EncryptAt(data, offset)
}

func (c *aesCipher) Encrypt(data []byte) []byte {
	return c.EncryptAt(data, 0)
}

func (c *aesCipher) Decrypt(data []byte) []byte {
	return c.DecryptAt(data, 0)
}
