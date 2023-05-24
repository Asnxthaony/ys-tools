package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"ys-tools/pkg/ec2b"
	"ys-tools/pkg/mi"
	"ys-tools/pkg/types/definepb"
)

const (
	GAME_VERSION = "3.7.0"
	LANG         = int32(definepb.LanguageType_LANGUAGE_SC)
	CHANNEL_ID   = int32(definepb.ChannelIdType_CHANNEL_ID_MIHOYO)
)

func main() {
	CHANNEL_NAME_LIST := []string{
		"CNRELWin",
		"CNRELiOS",
		"CNRELAndroid",
		"CNRELPS4",
		"CNCBPS4",
		"CNRELPS5",
		"CNCBPS5",
		"CNGMWin",
		"CNGMiOS",
		"CNGMAndroid",
		"CNGMPS4",
		"CNGMPS5",
		"CNPREWin",
		"CNPREiOS",
		"CNPREAndroid",
		"CNPREPS4",
		"CNPREPS5",
		"CNINWin",
		"CNINiOS",
		"CNINAndroid",
		"OSRELWin",
		"OSRELiOS",
		"OSRELAndroid",
		"OSRELPS4SIEE",
		"OSRELPS4SIEA",
		"OSCBPS4",
		"OSCBPS4SIEE",
		"OSCBPS4SIEA",
		"OSRELPS5SIEE",
		"OSRELPS5SIEA",
		"OSCBPS5",
		"OSCBPS5SIEE",
		"OSCBPS5SIEA",
		"OSGMWin",
		"OSGMiOS",
		"OSGMAndroid",
		"OSGMPS4",
		"OSPREWin",
		"OSPREiOS",
		"OSPREAndroid",
		"OSPREPS4",
		"CNCBWin",
		"CNCBiOS",
		"CNCBAndroid",
		"OSCBWin",
		"OSCBiOS",
		"OSCBAndroid",
	}

	var wg sync.WaitGroup

	for _, channelName := range CHANNEL_NAME_LIST {
		wg.Add(1)

		go func(channelName string) {
			defer wg.Done()

			version := channelName + GAME_VERSION
			log.Printf("Trying fetch region list for %s\n", version)

			regionList, err := mi.GetRegionList(version, LANG, CHANNEL_ID)
			if err != nil {
				log.Printf("[%s] Failed to get region list: %v", version, err)
				return
			}

			if regionList.Retcode != 0 {
				log.Printf("[%s] Bad retcode: %v", version, regionList.Retcode)
				//	return
			}

			ec2b, err := ec2b.Load(regionList.ClientSecretKey)
			if err != nil {
				log.Printf("[%s] Failed to load ec2b key: %v", version, err)
				return
			}

			clientCustomConfig := regionList.ClientCustomConfigEncrypted
			xor(clientCustomConfig, ec2b.Key())

			var v map[string]interface{}
			if err := json.Unmarshal(clientCustomConfig, &v); err != nil {
				log.Printf("[%s] Failed to unmarshal json: %v", version, err)
			}

			ctx, _ := json.MarshalIndent(v, "", "    ")
			fmt.Printf("==================== %s ====================\n", version)
			fmt.Println(string(ctx))
		}(channelName)

		wg.Wait()
	}

}

func xor(p, key []byte) {
	for i := 0; i < len(p); i++ {
		p[i] ^= key[i%4096]
	}
}
