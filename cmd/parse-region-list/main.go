package main

import (
	"encoding/json"
	"fmt"
	"log"
	"ys-tools/pkg/ec2b"
	"ys-tools/pkg/mi"
	"ys-tools/pkg/types/definepb"
)

const (
	VERSION    = "CNRELWin3.7.0"
	LANG       = int32(definepb.LanguageType_LANGUAGE_SC)
	CHANNEL_ID = int32(definepb.ChannelIdType_CHANNEL_ID_MIHOYO)
)

func main() {
	regionList, err := mi.GetRegionList(VERSION, LANG, CHANNEL_ID)
	if err != nil {
		log.Fatalln("Failed to get region list:", err)
	}

	ctx, _ := json.MarshalIndent(regionList, "", "    ")
	fmt.Println(string(ctx))

	if regionList.Retcode != 0 {
		return
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

	ctx, _ = json.MarshalIndent(v, "", "    ")
	fmt.Println(string(ctx))
}

func xor(p, key []byte) {
	for i := 0; i < len(p); i++ {
		p[i] ^= key[i%4096]
	}
}
