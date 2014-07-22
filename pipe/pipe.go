package pipe

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/titanous/noise/box"
)

type Config struct {
	Key      *box.Key
	EphKey   *box.Key
	PeerKey  *box.Key
	Cipher   box.Ciphersuite
	PadLen   int
	SkipAuth bool
}

type Conn struct {
	limitReader io.LimitedReader
	conn        io.ReadWriteCloser
	config      Config
	isClient    bool

	peerEphKey box.Key

	handshakeMtx      sync.Mutex
	handshakeComplete bool
	handshakeErr      error

	pendingData bool

	readMtx, writeMtx         sync.Mutex
	readLenBuf, writeLenBuf   [4]byte
	readBuf                   bytes.Buffer
	readCrypter, writeCrypter box.Crypter
}

func Client(conn io.ReadWriteCloser, config *Config) (*Conn, error) {
	if config.PeerKey == nil && !config.SkipAuth {
		return nil, errors.New("pipe: PeerKey unspecified without enabling SkipAuth")
	}
	c := &Conn{
		conn:        conn,
		config:      *config,
		limitReader: io.LimitedReader{R: conn},
	}
	if err := c.setupKeys(); err != nil {
		return nil, err
	}
	return c, nil
}

func Server(conn io.ReadWriteCloser, config *Config) (*Conn, error) {
	c := &Conn{
		conn:        conn,
		config:      *config,
		isClient:    true,
		limitReader: io.LimitedReader{R: conn},
	}
	if err := c.setupKeys(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Conn) setupKeys() error {
	if c.config.EphKey == nil {
		k, err := c.config.Cipher.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		c.config.EphKey = &k
	}
	if c.config.Key == nil {
		c.config.Key = c.config.EphKey
	}
	c.writeCrypter = box.Crypter{
		Cipher: c.config.Cipher,
		Key:    *c.config.Key,
	}
	if c.config.PeerKey != nil {
		c.writeCrypter.PeerKey.Public = c.config.PeerKey.Public
	}
	c.readCrypter = c.writeCrypter
	return nil
}

func (c *Conn) Handshake() error {
	c.handshakeMtx.Lock()
	defer c.handshakeMtx.Unlock()
	if c.handshakeErr != nil {
		return c.handshakeErr
	}
	if c.handshakeComplete {
		return nil
	}

	if c.isClient {
		c.handshakeErr = c.clientHandshake()
	} else {
		c.handshakeErr = c.serverHandshake()
	}
	c.handshakeComplete = true
	return c.handshakeErr
}

func (c *Conn) serverHandshake() error {
	keyLen, _ := c.config.Cipher.KeyLen()
	peerEphKey, err := c.readMessage(uint32(keyLen))
	if err != nil {
		return err
	}
	if len(peerEphKey) != keyLen {
		return errors.New("pipe: client key too short")
	}
	c.peerEphKey.Public = make([]byte, keyLen)
	copy(c.peerEphKey.Public, peerEphKey)

	serverHello, _ := c.writeCrypter.EncryptBox(nil, c.config.EphKey, nil, c.config.PadLen, 2)
	if err := c.writeMessage(serverHello); err != nil {
		return err
	}
	c.readCrypter.ChainVar = c.writeCrypter.ChainVar

	c.readBuf.Reset()
	c.readBuf.Write(peerEphKey)
	clientHelloBox, err := c.readMessage(0)
	if err != nil {
		return err
	}
	if _, err := c.readCrypter.DecryptBox(clientHelloBox, 4); err != nil {
		return err
	}

	kdfExtra := append(c.config.Cipher.AppendName(make([]byte, 0, 25)), 6)
	contexts := box.DeriveKey(c.readCrypter.ChainVar, make([]byte, box.CVLen), kdfExtra, c.config.Cipher.CCLen()*2)
	c.readCrypter.SetContext(contexts[:c.config.Cipher.CCLen()])
	c.writeCrypter.SetContext(contexts[c.config.Cipher.CCLen():])

	return nil
}

func (c *Conn) clientHandshake() error {
	if err := c.writeMessage(c.config.EphKey.Public); err != nil {
		return err
	}

	serverHelloBox, err := c.readMessage(0)
	if err != nil {
		return err
	}
	if _, err := c.readCrypter.DecryptBox(serverHelloBox, 2); err != nil {
		return err
	}
	c.writeCrypter.ChainVar = c.readCrypter.ChainVar

	clientHello, _ := c.writeCrypter.EncryptBox(nil, c.config.EphKey, nil, c.config.PadLen, 4)
	if err := c.writeMessage(clientHello[c.config.Cipher.DHLen():]); err != nil {
		return err
	}

	kdfExtra := append(c.config.Cipher.AppendName(make([]byte, 0, 25)), 6)
	contexts := box.DeriveKey(c.writeCrypter.ChainVar, make([]byte, box.CVLen), kdfExtra, c.config.Cipher.CCLen()*2)
	c.writeCrypter.SetContext(contexts[:c.config.Cipher.CCLen()])
	c.readCrypter.SetContext(contexts[c.config.Cipher.CCLen():])

	return nil
}

func (c *Conn) writeMessage(data []byte) error {
	binary.LittleEndian.PutUint32(c.writeLenBuf[:], uint32(len(data)))
	if _, err := c.conn.Write(c.writeLenBuf[:]); err != nil {
		return err
	}
	_, err := c.conn.Write(data)
	return err
}

var ErrMaxRead = errors.New("pipe: peer message length too big")

func (c *Conn) readMessage(maxLen uint32) ([]byte, error) {
	defer c.readBuf.Reset()
	_, err := io.ReadFull(c.conn, c.readLenBuf[:])
	if err != nil {
		return nil, err
	}
	readLen := binary.LittleEndian.Uint32(c.readLenBuf[:])
	if maxLen > 0 && readLen > maxLen {
		return nil, ErrMaxRead
	}
	c.limitReader.N = int64(readLen)
	n, err := c.readBuf.ReadFrom(&c.limitReader)
	if uint32(n) < readLen {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		err = unexpectedErr{err}
	}
	return c.readBuf.Bytes(), err
}

type unexpectedErr struct {
	error
}

func (c *Conn) Read(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	c.readMtx.Lock()
	defer c.readMtx.Unlock()

	if c.pendingData {
		n, err := c.readBuf.Read(p)
		if err == io.EOF {
			c.pendingData = false
		}
		return n, nil
	}

	ciphertext, err := c.readMessage(0)
	if e, ok := err.(unexpectedErr); ok {
		return 0, e.error
	}
	plaintext, err := c.readCrypter.DecryptBody(ciphertext, nil)
	if err != nil {
		return 0, err
	}
	if len(plaintext) > len(p) {
		c.pendingData = true
		c.readBuf.Reset()
		c.readBuf.Write(plaintext)
		n, _ := c.readBuf.Read(p)
		return n, nil
	}
	return copy(p, plaintext), nil
}

func (c *Conn) Write(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMtx.Lock()
	defer c.writeMtx.Unlock()

	body := c.writeCrypter.EncryptBody(nil, p, nil, c.config.PadLen)
	if err := c.writeMessage(body); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *Conn) Close() error {
	return c.conn.Close()
}
