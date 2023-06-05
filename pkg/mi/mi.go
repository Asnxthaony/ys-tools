package mi

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"ys-tools/pkg/ec2b"
	"ys-tools/pkg/types/definepb"

	"google.golang.org/protobuf/proto"
)

const (
	OS_PREFIX   = "OS"
	OSCB_PREFIX = "OSCB"
)

var (
	pubKeys  map[string]*PublicKey
	privKeys map[string]*PrivateKey
)

func init() {
	pubKeys = make(map[string]*PublicKey)
	privKeys = make(map[string]*PrivateKey)

	if err := loadSecrets(); err != nil {
		panic(err)
	}
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

func GetRegionList(version string, lang int32, channelId int32) (*definepb.QueryRegionListHttpRsp, error) {
	dispatchHost := "dispatchcnglobal.yuanshen.com"
	if strings.HasPrefix(version, OS_PREFIX) {
		dispatchHost = "dispatchosglobal.yuanshen.com"
	}
	platform := GetPlatformByVersion(version)

	url := fmt.Sprintf("https://%s/query_region_list?version=%s&lang=%d&platform=%d&binary=1&channel_id=%d", dispatchHost, version, lang, platform, channelId)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return &definepb.QueryRegionListHttpRsp{}, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &definepb.QueryRegionListHttpRsp{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &definepb.QueryRegionListHttpRsp{}, fmt.Errorf("status is not ok, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &definepb.QueryRegionListHttpRsp{}, err
	}

	content, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return &definepb.QueryRegionListHttpRsp{}, err
	}

	regionList := &definepb.QueryRegionListHttpRsp{}
	if err := proto.Unmarshal(content, regionList); err != nil {
		return &definepb.QueryRegionListHttpRsp{}, err
	}

	return regionList, nil
}

func GetCurrRegion(version string, lang int32, channelId int32, accountType int32, dispatchSeed string) (*definepb.QueryCurrRegionHttpRsp, error) {
	dispatchHost := "https://cngfdispatch.yuanshen.com"
	keyId := "4"
	if strings.HasPrefix(version, OS_PREFIX) {
		if strings.HasPrefix(version, OSCB_PREFIX) {
			dispatchHost = "http://18.222.82.186:22401"
		} else {
			dispatchHost = "https://osasiadispatch.yuanshen.com"
		}
		keyId = "5"
	}
	platform := GetPlatformByVersion(version)

	url := fmt.Sprintf("%s/query_cur_region?version=%s&lang=%d&platform=%d&binary=1&channel_id=%d&sub_channel_id=0&account_type=1&dispatchSeed=%s&key_id=%s", dispatchHost, version, lang, platform, channelId, dispatchSeed, keyId)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return &definepb.QueryCurrRegionHttpRsp{}, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &definepb.QueryCurrRegionHttpRsp{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &definepb.QueryCurrRegionHttpRsp{}, fmt.Errorf("status is not ok, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &definepb.QueryCurrRegionHttpRsp{}, err
	}

	var v map[string]string
	if err := json.Unmarshal(body, &v); err != nil {
		return &definepb.QueryCurrRegionHttpRsp{}, err
	}

	content, err := base64.StdEncoding.DecodeString(string(v["content"]))
	if err != nil {
		return &definepb.QueryCurrRegionHttpRsp{}, err
	}

	content, err = privKeys[keyId].Decrypt(content)
	if err != nil {
		return &definepb.QueryCurrRegionHttpRsp{}, err
	}

	sign, err := base64.StdEncoding.DecodeString(string(v["sign"]))
	if err != nil {
		return &definepb.QueryCurrRegionHttpRsp{}, err
	}

	if err := pubKeys[keyId].Verify(content, sign); err != nil {
		return &definepb.QueryCurrRegionHttpRsp{}, err
	}

	currRegion := &definepb.QueryCurrRegionHttpRsp{}
	if err := proto.Unmarshal(content, currRegion); err != nil {
		return &definepb.QueryCurrRegionHttpRsp{}, err
	}

	return currRegion, nil
}

func DecryptEncryptedCustomConfig(clientSecretKey, encryptedCustomConfig []byte) ([]byte, error) {
	ec2b, err := ec2b.Load(clientSecretKey)
	if err != nil {
		return nil, errors.New("failed to load ec2b key")
	}

	regionCustomConfig := encryptedCustomConfig
	xor(regionCustomConfig, ec2b.Key())

	return regionCustomConfig, nil
}

func GetPlatformByVersion(version string) int32 {
	if strings.Contains(version, "iOS") {
		return int32(definepb.PlatformType_IOS)
	} else if strings.Contains(version, "Android") {
		return int32(definepb.PlatformType_ANDROID)
	} else if strings.Contains(version, "Win") {
		return int32(definepb.PlatformType_PC)
	} else if strings.Contains(version, "PS4") {
		return int32(definepb.PlatformType_PS4)
	} else if strings.Contains(version, "PS5") {
		return int32(definepb.PlatformType_PS5)
	}

	return int32(definepb.PlatformType_EDITOR)
}

func xor(p, key []byte) {
	for i := 0; i < len(p); i++ {
		p[i] ^= key[i%4096]
	}
}
