package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"ys-tools/pkg/ec2b"
	"ys-tools/pkg/types/definepb"

	"google.golang.org/protobuf/proto"
)

const (
	VERSION = "CNRELWin3.6.0"
)

func main() {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://dispatchcnglobal.yuanshen.com/query_region_list?version=%s&lang=2&platform=3&binary=1&channel_id=1", VERSION), nil)
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

	content, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		log.Fatalln("Failed to decode base64 string:", err)
	}

	regionList := &definepb.QueryRegionListHttpRsp{}
	if err := proto.Unmarshal(content, regionList); err != nil {
		log.Fatalln("Failed to parse RegionList:", err)
	}

	if regionList.Retcode != 0 {
		log.Fatalln("Bad response, retCode:", regionList.Retcode)
	}

	ec2b, err := ec2b.Load(regionList.ClientSecretKey)
	if err != nil {
		log.Fatalln("Failed to load ec2b key:", err)
	}

	clientCustomConfig := regionList.ClientCustomConfigEncrypted
	xor(clientCustomConfig, ec2b.Key())

	var v map[string]interface{}
	if err := json.Unmarshal(clientCustomConfig, &v); err != nil {
		log.Fatalln("Failed to unmarshal json:", err)
	}

	ctx, _ := json.MarshalIndent(v, "", "    ")
	fmt.Println(string(ctx))
}

func xor(p, key []byte) {
	for i := 0; i < len(p); i++ {
		p[i] ^= key[i%4096]
	}
}
