package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"ys-tools/pkg/ec2b"
	"ys-tools/pkg/types/definepb"

	"google.golang.org/protobuf/proto"
)

const (
	DISPATCH_HOST = "cngfdispatch.yuanshen.com"
	VERSION       = "CNRELWin3.7.0"
	LANG          = definepb.LanguageType_LANGUAGE_SC
	PLATFORM      = definepb.PlatformType_PC
	CHANNEL_ID    = definepb.ChannelIdType_CHANNEL_ID_MIHOYO
	ACCOUNT_TYPE  = definepb.AccountType_ACCOUNT_MIHOYO
	DISPATCH_SEED = "916fa790e214f718"
	KEY_ID        = "4"
)

var (
	pubKeys  map[string]*PublicKey
	privKeys map[string]*PrivateKey
)

type PublicKey struct {
	*rsa.PublicKey
}

type PrivateKey struct {
	*rsa.PrivateKey
}

func main() {
	pubKeys = make(map[string]*PublicKey)
	privKeys = make(map[string]*PrivateKey)

	if err := loadSecrets(); err != nil {
		panic(err)
	}

	url := fmt.Sprintf("https://%s/query_cur_region?version=%s&lang=%d&platform=%d&binary=1&channel_id=%d&sub_channel_id=0&account_type=1&dispatchSeed=%s&key_id=%s", DISPATCH_HOST, VERSION, LANG, PLATFORM, CHANNEL_ID, DISPATCH_SEED, KEY_ID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		panic(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalln("status is not ok")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	var v map[string]string
	if err := json.Unmarshal(body, &v); err != nil {
		log.Fatalln("Failed to unmarshal json:", err)
	}

	content, err := base64.StdEncoding.DecodeString(string(v["content"]))
	if err != nil {
		log.Fatalln("Failed to decode content:", err)
	}

	content, err = privKeys[KEY_ID].Decrypt(content)
	if err != nil {
		log.Fatalln("Failed to decrypt content:", err)
	}

	sign, err := base64.StdEncoding.DecodeString(string(v["sign"]))
	if err != nil {
		log.Fatalln("Failed to decode sign:", err)
	}

	if err := pubKeys[KEY_ID].Verify(content, sign); err != nil {
		log.Fatalln("Failed to verify sign:", err)
	}

	currRegion := &definepb.QueryCurrRegionHttpRsp{}
	if err := proto.Unmarshal(content, currRegion); err != nil {
		log.Fatalln("Failed to parse CurrRegion:", err)
	}

	if currRegion.Retcode != 0 {
		log.Fatalln("Bad response, retCode:", currRegion.Retcode)
	}

	ctx, _ := json.MarshalIndent(currRegion, "", "    ")
	fmt.Println(string(ctx))

	ec2b, err := ec2b.Load(currRegion.ClientSecretKey)
	if err != nil {
		log.Fatalln("Failed to load ec2b key:", err)
	}

	regionCustomConfig := currRegion.RegionCustomConfigEncrypted
	xor(regionCustomConfig, ec2b.Key())

	var vv map[string]interface{}
	if err := json.Unmarshal(regionCustomConfig, &vv); err != nil {
		log.Fatalln("Failed to unmarshal json:", err)
	}

	ctx, _ = json.MarshalIndent(vv, "", "    ")
	fmt.Println(string(ctx))
}

func xor(p, key []byte) {
	for i := 0; i < len(p); i++ {
		p[i] ^= key[i%4096]
	}
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

func loadSecrets() error {
	rest, _ := os.ReadFile("data/secret.pem")
	var block *pem.Block
	for {
		block, rest = pem.Decode(rest)
		switch block.Type {
		case "DISPATCH SERVER RSA PUBLIC KEY 1":
			k, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return err
			} else if k, ok := k.(*rsa.PublicKey); !ok {
				return errors.New("invalid public key")
			} else {
				pubKeys["1"] = &PublicKey{k}
			}
		case "DISPATCH SERVER RSA PUBLIC KEY 2":
			k, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return err
			} else if k, ok := k.(*rsa.PublicKey); !ok {
				return errors.New("invalid public key")
			} else {
				pubKeys["2"] = &PublicKey{k}
			}
		case "DISPATCH SERVER RSA PUBLIC KEY 3":
			k, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return err
			} else if k, ok := k.(*rsa.PublicKey); !ok {
				return errors.New("invalid public key")
			} else {
				pubKeys["3"] = &PublicKey{k}
			}
		case "DISPATCH SERVER RSA PUBLIC KEY 4":
			k, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return err
			} else if k, ok := k.(*rsa.PublicKey); !ok {
				return errors.New("invalid public key")
			} else {
				pubKeys["4"] = &PublicKey{k}
			}
		case "DISPATCH SERVER RSA PUBLIC KEY 5":
			k, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return err
			} else if k, ok := k.(*rsa.PublicKey); !ok {
				return errors.New("invalid public key")
			} else {
				pubKeys["5"] = &PublicKey{k}
			}
		case "DISPATCH CLIENT RSA PRIVATE KEY 1":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return err
			} else if k, ok := k.(*rsa.PrivateKey); !ok {
				return errors.New("invalid private key")
			} else {
				privKeys["1"] = &PrivateKey{k}
			}
		case "DISPATCH CLIENT RSA PRIVATE KEY 2":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return err
			} else if k, ok := k.(*rsa.PrivateKey); !ok {
				return errors.New("invalid private key")
			} else {
				privKeys["2"] = &PrivateKey{k}
			}
		case "DISPATCH CLIENT RSA PRIVATE KEY 3":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return err
			} else if k, ok := k.(*rsa.PrivateKey); !ok {
				return errors.New("invalid private key")
			} else {
				privKeys["3"] = &PrivateKey{k}
			}
		case "DISPATCH CLIENT RSA PRIVATE KEY 4":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return err
			} else if k, ok := k.(*rsa.PrivateKey); !ok {
				return errors.New("invalid private key")
			} else {
				privKeys["4"] = &PrivateKey{k}
			}
		case "DISPATCH CLIENT RSA PRIVATE KEY 5":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return err
			} else if k, ok := k.(*rsa.PrivateKey); !ok {
				return errors.New("invalid private key")
			} else {
				privKeys["5"] = &PrivateKey{k}
			}
		}
		if len(rest) == 0 {
			break
		}
	}
	return nil
}
