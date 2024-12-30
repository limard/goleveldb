package leveldb

import (
	"sync/atomic"

	"github.com/syndtr/goleveldb/leveldb/crypto"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

var EncryptionKey []byte

type iStorage struct {
	storage.Storage
	read  uint64
	write uint64
}

func (c *iStorage) Open(fd storage.FileDesc) (storage.Reader, error) {
	r, err := c.Storage.Open(fd)
	if EncryptionKey == nil {
		return &iStorageReader{r, c, nil, 0}, err
	}
	cipher := crypto.NewCipher(EncryptionKey)
	return &iStorageReader{r, c, cipher, 0}, err
}

func (c *iStorage) Create(fd storage.FileDesc) (storage.Writer, error) {
	w, err := c.Storage.Create(fd)
	if EncryptionKey == nil {
		return &iStorageWriter{w, c, nil, 0}, err
	}
	cipher := crypto.NewCipher(EncryptionKey)
	return &iStorageWriter{w, c, cipher, 0}, err
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
	cipher *crypto.Cipher
	offset int64
}

func (r *iStorageReader) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	if err != nil {
		return
	}
	if r.cipher != nil {
		decrypted := r.cipher.DecryptAt(p[:n], r.offset)
		copy(p, decrypted)
	}
	r.offset += int64(n)
	atomic.AddUint64(&r.c.read, uint64(n))
	return n, err
}

func (r *iStorageReader) ReadAt(p []byte, off int64) (n int, err error) {
	n, err = r.Reader.ReadAt(p, off)
	if err != nil {
		return
	}
	if r.cipher != nil {
		decrypted := r.cipher.DecryptAt(p[:n], off)
		copy(p, decrypted)
	}
	atomic.AddUint64(&r.c.read, uint64(n))
	return n, err
}

type iStorageWriter struct {
	storage.Writer
	c      *iStorage
	cipher *crypto.Cipher
	offset int64
}

func (w *iStorageWriter) Write(p []byte) (n int, err error) {
	if w.cipher != nil {
		encrypted := w.cipher.EncryptAt(p, w.offset)
		n, err = w.Writer.Write(encrypted)
		if err != nil {
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
