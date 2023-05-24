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
	VERSION       = "CNRELWin3.7.0"
	LANG          = int32(definepb.LanguageType_LANGUAGE_SC)
	CHANNEL_ID    = int32(definepb.ChannelIdType_CHANNEL_ID_MIHOYO)
	ACCOUNT_TYPE  = int32(definepb.AccountType_ACCOUNT_MIHOYO)
	DISPATCH_SEED = "916fa790e214f718"
)

func main() {
	currRegion, err := mi.GetCurrRegion(VERSION, LANG, CHANNEL_ID, ACCOUNT_TYPE, DISPATCH_SEED)
	if err != nil {
		log.Fatalln("Failed to get curr region:", err)
	}

	ctx, _ := json.MarshalIndent(currRegion, "", "    ")
	fmt.Println(string(ctx))

	if currRegion.Retcode != 0 {
		return
	}

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
