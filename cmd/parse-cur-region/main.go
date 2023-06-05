package main

import (
	"encoding/json"
	"fmt"
	"log"
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

	regionCustomConfig, err := mi.DecryptEncryptedCustomConfig(currRegion.ClientSecretKey, currRegion.RegionCustomConfigEncrypted)
	if err != nil {
		log.Fatalln("Failed to decrypt region custom config:", err)
	}

	var vv map[string]interface{}
	if err := json.Unmarshal(regionCustomConfig, &vv); err != nil {
		log.Fatalln("Failed to unmarshal json:", err)
	}

	ctx, _ = json.MarshalIndent(vv, "", "    ")
	fmt.Println(string(ctx))
}
