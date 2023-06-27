package ec2b

import (
	"encoding/binary"
	"errors"

	"ys-tools/pkg/rand/mt19937"
)

var ErrInvalidKey = errors.New("invalid ec2b key")

type Ec2b struct {
	key  []byte
	data []byte
	seed uint64
	temp []byte
}

func Load(b []byte) (*Ec2b, error) {
	if len(b) < 2076 { // Magic(4) + KeyLen(4) + Key(16) + DataLen(4) + Data(2048)
		return nil, ErrInvalidKey
	}

	if string(b[0:4]) != "Ec2b" {
		return nil, ErrInvalidKey
	}

	keyLen := binary.LittleEndian.Uint32(b[4:8])
	if keyLen != 16 {
		return nil, ErrInvalidKey
	}

	dataLen := binary.LittleEndian.Uint32(b[24:28])
	if dataLen != 2048 {
		return nil, ErrInvalidKey
	}

	e := &Ec2b{
		key:  b[8:24],
		data: b[28 : 28+2048],
	}
	e.init()

	return e, nil
}

func (e *Ec2b) init() {
	k := make([]byte, 16)
	copy(k[:], e.key)
	keyScramble(k)
	e.SetSeed(getSeed(k, e.data))
}

func getSeed(key, data []byte) uint64 {
	v := ^uint64(0xCEAC3B5A867837AC)
	v ^= binary.LittleEndian.Uint64(key[0:8])
	v ^= binary.LittleEndian.Uint64(key[8:16])

	for i := 0; i < len(data); i += 8 {
		v ^= binary.LittleEndian.Uint64(data[i:])
	}

	return v
}

func (e *Ec2b) SetSeed(seed uint64) {
	e.seed = seed

	r := mt19937.NewRand64()
	r.Seed(int64(e.seed))

	e.temp = make([]byte, 4096)
	for i := 0; i < len(e.temp); i += 8 {
		binary.LittleEndian.PutUint64(e.temp[i:], r.Uint64())
	}
}

func (e *Ec2b) Seed() uint64 { return e.seed }
func (e *Ec2b) Key() []byte  { return e.temp }

func (e *Ec2b) Xor(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] ^= e.temp[i%4096]
	}
}

func keyScramble(key []byte) {
	_ = key[15] // early bounds check
	s0 := binary.BigEndian.Uint32(key[0:4])
	s1 := binary.BigEndian.Uint32(key[4:8])
	s2 := binary.BigEndian.Uint32(key[8:12])
	s3 := binary.BigEndian.Uint32(key[12:16])

	// First round just XORs input with key.
	s0 ^= xk[0]
	s1 ^= xk[1]
	s2 ^= xk[2]
	s3 ^= xk[3]

	// Middle rounds shuffle using tables.
	// Number of rounds is set by length of expanded key.
	nr := len(xk)/4 - 2 // - 2: one above, one more below
	k := 4
	var t0, t1, t2, t3 uint32
	for r := 0; r < nr; r++ {
		t0 = xk[k+0] ^ td0[uint8(s0>>24)] ^ td1[uint8(s3>>16)] ^ td2[uint8(s2>>8)] ^ td3[uint8(s1)]
		t1 = xk[k+1] ^ td0[uint8(s1>>24)] ^ td1[uint8(s0>>16)] ^ td2[uint8(s3>>8)] ^ td3[uint8(s2)]
		t2 = xk[k+2] ^ td0[uint8(s2>>24)] ^ td1[uint8(s1>>16)] ^ td2[uint8(s0>>8)] ^ td3[uint8(s3)]
		t3 = xk[k+3] ^ td0[uint8(s3>>24)] ^ td1[uint8(s2>>16)] ^ td2[uint8(s1>>8)] ^ td3[uint8(s0)]
		k += 4
		s0, s1, s2, s3 = t0, t1, t2, t3
	}

	// Last round uses s-box directly and XORs to produce output.
	s0 = uint32(sbox1[t0>>24])<<24 | uint32(sbox1[t3>>16&0xff])<<16 | uint32(sbox1[t2>>8&0xff])<<8 | uint32(sbox1[t1&0xff])
	s1 = uint32(sbox1[t1>>24])<<24 | uint32(sbox1[t0>>16&0xff])<<16 | uint32(sbox1[t3>>8&0xff])<<8 | uint32(sbox1[t2&0xff])
	s2 = uint32(sbox1[t2>>24])<<24 | uint32(sbox1[t1>>16&0xff])<<16 | uint32(sbox1[t0>>8&0xff])<<8 | uint32(sbox1[t3&0xff])
	s3 = uint32(sbox1[t3>>24])<<24 | uint32(sbox1[t2>>16&0xff])<<16 | uint32(sbox1[t1>>8&0xff])<<8 | uint32(sbox1[t0&0xff])

	s0 ^= xk[k+0]
	s1 ^= xk[k+1]
	s2 ^= xk[k+2]
	s3 ^= xk[k+3]

	_ = key[15] // early bounds check
	binary.BigEndian.PutUint32(key[0:4], s0)
	binary.BigEndian.PutUint32(key[4:8], s1)
	binary.BigEndian.PutUint32(key[8:12], s2)
	binary.BigEndian.PutUint32(key[12:16], s3)

	for i := 0; i < 16; i++ {
		key[i] ^= iv[i]
	}
}
