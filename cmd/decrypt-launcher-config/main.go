package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"io"
	"log"
	"os"
)

var (
	key = [8]byte{0x23, 0xF0, 0xB7, 0xAC, 0x23, 0xD3, 0x2A, 0x0C}
)

func main() {
	p, err := os.ReadFile("data/hkrpg_os_32.txt")
	if err != nil {
		panic(err)
	}

	cipher, err := base64.StdEncoding.DecodeString(string(p))
	if err != nil {
		panic(err)
	}

	cipherVersion := cipher[0]
	if cipherVersion != 3 {
		panic("Invalid version or not a cyphertext.")
	}

	cipherType := cipher[1]
	println("Type: ", cipherType, "Version:", cipherVersion)

	cipher = cipher[2:]
	decrypted := make([]byte, len(cipher))

	var prev byte
	for i := 0; i < len(cipher); i++ {
		curr := cipher[i]

		temp := cipher[i] ^ key[i%len(key)] ^ prev
		decrypted[i] = temp

		prev = curr
	}

	// remove checksum
	decrypted, err = ZlibDecompress(decrypted[7:])
	if err != nil {
		panic(err)
	}

	log.Printf("%s", decrypted)
}

func ZlibDecompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	data, err = io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return data, r.Close()
}
