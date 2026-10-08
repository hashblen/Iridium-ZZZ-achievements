package main

import (
	"encoding/json"
	"flag"
	"github.com/fatih/color"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
	"log"
	"os"
)

type Config struct {
	DeviceName        string   `json:"deviceName"`
	PacketFilter      []string `json:"packetFilter"`
	AutoSavePcapFiles bool     `json:"autoSavePcapFiles"`

	// AutoFindMinimalProto deduces the packets it needs from the wire instead of
	// loading protos: the login seed is found by RSA round-trip and the
	// achievement lists by matching ids against the stardb.gg catalogue, which
	// also recovers any XOR key on the ids. Needs no proto/, no packetIds.json
	// and no knowledge of the obfuscation constants; the results are written to
	// ./out/ for reuse.
	AutoFindMinimalProto bool `json:"autoFindMinimalProto"`
}

var config *Config
var listDevice = flag.Bool("l", false, "List the network devices on this machine")
var ip = flag.String("ip", "", "Designate the network devices to capture by IP")
var pcapIn = flag.String("pcap", "", "Read from a .pcapng file instead of a live device. "+
	"The HTTP server still runs so the frontend can show the result.")
var xor = flag.Bool("xor", false,
	"Apply the `// xor: N` per-field constants when decoding, so the frontend shows real "+
		"values instead of obfuscated ones. Off by default because the constants are not "+
		"uniformly enforced by the game: `retcode` is annotated in 24 protos yet never "+
		"appears on the wire, so -xor on makes successful responses report a nonzero retcode.")

func main() {
	bytes, err := ioutil.ReadFile("./config.json")
	if err != nil {
		log.Fatalln("Could not load ./config.json", err)
	}
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		log.Fatalln("Could not load ./config.json", err)
	}
	for packet := range config.PacketFilter {
		packetFilter[config.PacketFilter[packet]] = true
	}

	flag.Parse()

	xorEnabled = *xor

	if *listDevice {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		log.Println(color.RedString("Name"), "\tDescription\t", color.CyanString("IP address"), "\tSubnet mask")
		for _, device := range devices {
			log.Println(color.RedString(device.Name), "\t", device.Description, "\t")
			for _, address := range device.Addresses {
				log.Println("\t\t\t", color.CyanString(address.IP.String()), "\t", address.Netmask)
			}
		}
		os.Exit(0)
	}

	if len(*ip) > 0 {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		for _, device := range devices {
			for _, address := range device.Addresses {
				if address.IP.String() == *ip {
					log.Println("Device ", device.Name, " is chose")
					config.DeviceName = device.Name
					break
				}
			}
		}
	}

	go InitProto()

	if *pcapIn != "" {
		go openPcap(*pcapIn)
	}

	startServer()
}
