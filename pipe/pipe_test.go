package pipe

import (
	"io"
	"testing"

	"github.com/titanous/noise/box"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type S struct{}

var _ = Suite(&S{})

type rwc struct {
	io.Reader
	io.WriteCloser
}

func (s *S) TestRoundtrip(c *C) {
	serverR, clientW := io.Pipe()
	clientR, serverW := io.Pipe()

	sk, err := box.Noise255.GenerateKey(nil)
	c.Assert(err, IsNil)
	ck, err := box.Noise255.GenerateKey(nil)
	c.Assert(err, IsNil)
	serverConfig := &Config{
		Cipher:  box.Noise255,
		Key:     &sk,
		PeerKey: &box.Key{Public: ck.Public},
	}
	clientConfig := &Config{
		Cipher:  box.Noise255,
		Key:     &ck,
		PeerKey: &box.Key{Public: sk.Public},
	}

	server, err := Server(&rwc{serverR, serverW}, serverConfig)
	c.Assert(err, IsNil)
	client, err := Client(&rwc{clientR, clientW}, clientConfig)
	c.Assert(err, IsNil)

	ch := make(chan error)
	msg := []byte("yellow submarine")
	res := make([]byte, 16)
	var readN int
	go func() {
		var err error
		readN, err = server.Read(res)
		ch <- err
	}()

	n, err := client.Write(msg)
	c.Assert(err, IsNil)
	c.Assert(n, Equals, len(msg))
	c.Assert(<-ch, IsNil)
	c.Assert(readN, Equals, len(res))
	c.Assert(res, DeepEquals, msg)

	go func() {
		res = make([]byte, 16)
		var err error
		readN, err = client.Read(res)
		ch <- err
	}()

	n, err = server.Write(msg)
	c.Assert(err, IsNil)
	c.Assert(n, Equals, len(msg))
	c.Assert(<-ch, IsNil)
	c.Assert(readN, Equals, len(res))
	c.Assert(res, DeepEquals, msg)
}
