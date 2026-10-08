package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/xtaci/kcp-go"
)

type Packet struct {
	Time       int64       `json:"time"`
	FromServer bool        `json:"fromServer"`
	PacketId   uint16      `json:"packetId"`
	PacketName string      `json:"packetName"`
	Object     interface{} `json:"object"`
	Raw        []byte      `json:"raw"`
}

var playerGetTokenCsReqId uint16
var playerGetTokenScRspId uint16

var serverSeed uint64
var sentMs uint64

// sessionKey is the negotiated key, set once the seed has been recovered.
var sessionKey []byte

// initialKeys are the shipped session keys, newest first, from ./data/Keys.json.
// Several are kept because the key rotates with every game update and a capture
// taken under an older build still has to decrypt.
var initialKeys [][]byte

// initialKeyNames parallels initialKeys, for logging which build a key belongs to.
var initialKeyNames []string

// activeInitialKey caches which shipped key decrypted this capture, so pickPad
// does not retest every key on every packet.
var activeInitialKey []byte

var privateKey *rsa.PrivateKey

var captureHandler *pcap.Handle
var kcpMap map[string]*kcp.KCP
var packetFilter = make(map[string]bool)
var pcapFile *os.File

func openPcap(fileName string) {
	readKeys()
	var err error
	captureHandler, err = pcap.OpenOffline(fileName)
	if err != nil {
		log.Println("Could not open pacp file", err)
		return
	}
	startSniffer()
}

func openCapture() {
	readKeys()
	var err error
	captureHandler, err = pcap.OpenLive(config.DeviceName, 1500, true, -1)
	if err != nil {
		log.Println("Could not open capture", err)
		return
	}

	if config.AutoSavePcapFiles {
		pcapFile, err = os.Create(time.Now().Format("06-01-02 15.04.05") + ".pcapng")
		if err != nil {
			log.Println("Could not create pcapng file", err)
		}
		defer pcapFile.Close()
	}

	startSniffer()
}

func closeHandle() {
	if captureHandler != nil {
		captureHandler.Close()
		captureHandler = nil
	}
	if pcapFile != nil {
		pcapFile.Close()
		pcapFile = nil
	}
}

// readKeys loads the decryption keys and the RSA key.
//
// Keys.json is read in file order and tried last-first, so the newest key is the
// one appended last. Which is "right" is decided by testing against the traffic
// rather than by the version string, since the version is only a label. That way
// a capture from an older build still decrypts after an update.
func readKeys() {
	keys, names, err := loadKeys("./data/Keys.json")
	if err != nil {
		log.Println("Could not load ./data/Keys.json:", err)
		log.Println("Falling back to the legacy single-key ./data/Key.txt")
		keys, names, err = loadLegacyKey("./data/Key.txt")
		if err != nil {
			log.Fatalln("Could not load any decryption key:", err)
		}
	}
	initialKeys = keys
	initialKeyNames = names
	log.Printf("Loaded %d initial key(s), newest first: %v", len(keys), names)

	// Auto-detect mode may have no packetIds.json yet; the lookups return zero.
	packetIdMap = make(map[uint16]string)
	if raw, err := os.ReadFile("./data/packetIds.json"); err == nil {
		if err := json.Unmarshal(raw, &packetIdMap); err != nil {
			log.Println("Could not parse ./data/packetIds.json:", err)
			packetIdMap = make(map[uint16]string)
		}
	}
	for k, v := range packetIdMap {
		packetNameMap[v] = k
	}
	playerGetTokenCsReqId = packetNameMap["PlayerGetTokenCsReq"]
	playerGetTokenScRspId = packetNameMap["PlayerGetTokenScRsp"]

	readPrivateKey("data/private_3.pem")
}

// loadKeys returns the keys newest-first, i.e. reversed from file order.
func loadKeys(path string) ([][]byte, []string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	pairs, err := decodeKeyPairs(raw)
	if err != nil {
		return nil, nil, err
	}
	if len(pairs) == 0 {
		return nil, nil, errors.New("no keys present")
	}

	var keys [][]byte
	var names []string
	for i := len(pairs) - 1; i >= 0; i-- {
		// Keys are written without base64 padding; accept either form.
		dec, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(pairs[i].value))
		if err != nil {
			dec, err = base64.StdEncoding.DecodeString(strings.TrimSpace(pairs[i].value))
			if err != nil {
				log.Printf("Skipping key %q: not valid base64: %v", pairs[i].key, err)
				continue
			}
		}
		if len(dec) == 0 {
			log.Printf("Skipping key %q: decodes to nothing", pairs[i].key)
			continue
		}
		keys = append(keys, dec)
		names = append(names, pairs[i].key)
	}
	if len(keys) == 0 {
		return nil, nil, errors.New("no keys decoded")
	}
	return keys, names, nil
}

// decodeKeyPairs preserves file order, which unmarshalling into a map would lose.
func decodeKeyPairs(raw []byte) ([]struct{ key, value string }, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("expected a JSON object")
	}
	var out []struct{ key, value string }
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("expected a string key")
		}
		tok, err = dec.Token()
		if err != nil {
			return nil, err
		}
		val, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("key %q does not hold a string", key)
		}
		out = append(out, struct{ key, value string }{key, val})
	}
	return out, nil
}

func loadLegacyKey(path string) ([][]byte, []string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	dec, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		dec, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, nil, err
		}
	}
	if len(dec) == 0 {
		return nil, nil, errors.New("key decodes to nothing")
	}
	return [][]byte{dec}, []string{"Key.txt"}, nil
}

func readPrivateKey(path string) {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatalln("Could not read private key @ "+path, err)
	}
	for {
		block, rest := pem.Decode(file)
		if block == nil {
			log.Fatalln("failed to parse private key @ " + path)
		}
		if block.Type != "RSA PRIVATE KEY" {
			file = rest
			continue
		}
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalln("failed to parse private key @ "+path, err)
		}
		privateKey = k
		return
	}
}

func startSniffer() {
	defer captureHandler.Close()

	err := captureHandler.SetBPFFilter("udp portrange 20501-20502")
	if err != nil {
		log.Println("Could not set the filter of capture")
		return
	}

	packetSource := gopacket.NewPacketSource(captureHandler, captureHandler.LinkType())
	packetSource.NoCopy = true

	kcpMap = make(map[string]*kcp.KCP)

	var pcapWriter *pcapgo.NgWriter
	if pcapFile != nil {
		pcapWriter, err = pcapgo.NewNgWriter(pcapFile, captureHandler.LinkType())
		if err != nil {
			log.Println("Could not create pcapng writer", err)
		}
	}

	for packet := range packetSource.Packets() {
		if pcapWriter != nil {
			err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Println("Could not write packet to pcap file", err)
			}
		}

		capTime := packet.Metadata().Timestamp
		data := packet.ApplicationLayer().Payload()
		udp := packet.TransportLayer().(*layers.UDP)
		fromServer := udp.SrcPort == 20501 || udp.SrcPort == 20502

		if len(data) <= 20 {
			handleSpecialPacket(data, fromServer, capTime)
			continue
		}

		handleKcp(data, fromServer, capTime)
	}
}

func handleKcp(data []byte, fromServer bool, capTime time.Time) {
	//log.Println("Data in KCP:", base64.RawStdEncoding.EncodeToString(data))
	data = reformData(data)
	//log.Println("Data after reformat:", base64.RawStdEncoding.EncodeToString(data))
	conv := binary.LittleEndian.Uint32(data[:4])
	key := strconv.Itoa(int(conv))
	if fromServer {
		key += "svr"
	} else {
		key += "cli"
	}

	if _, ok := kcpMap[key]; !ok {
		kcpInstance := kcp.NewKCP(conv, func(buf []byte, size int) {})
		kcpInstance.WndSize(1024, 1024)
		kcpMap[key] = kcpInstance
	}
	kcpInstance := kcpMap[key]
	_ = kcpInstance.Input(data, true, true)

	size := kcpInstance.PeekSize()
	for size > 0 {
		kcpBytes := make([]byte, size)
		kcpInstance.Recv(kcpBytes)
		handleProtoPacket(kcpBytes, fromServer, capTime)
		size = kcpInstance.PeekSize()
	}
	kcpInstance.Update()
}

func handleSpecialPacket(data []byte, fromServer bool, timestamp time.Time) {
	// A short frame means a connect or disconnect, so every session-scoped
	// value is stale from here on: the key, the seed, and anything detection
	// concluded. Without this a reconnect would keep the previous session's
	// state and mix two sessions' packets together.
	sessionKey = nil
	resetAutoDetect()

	switch binary.BigEndian.Uint32(data[:4]) {
	case 0xFF:
		buildPacketToSend(data, fromServer, timestamp, 0, "Hamdshanke pls.")
		break
	case 404:
		buildPacketToSend(data, fromServer, timestamp, 0, "Disconnected.")
		break
	default:
		buildPacketToSend(data, fromServer, timestamp, 0, "Hamdshanke estamblished.")
		break
	}
}

func handleProtoPacket(data []byte, fromServer bool, timestamp time.Time) {
	if binary.BigEndian.Uint32(data[:4]) != 0x01234567 {
		log.Fatal("Head magic is wrong")
	}

	packetId := binary.BigEndian.Uint16(data[4:6])
	var objectJson interface{}

	_, body := getHeaderAndBody(data)
	if body == nil {
		return
	}
	data = body

	// Auto-detect mode: no protos, no packet ids, no known XOR keys. Each stage
	// below is guarded so a capture that never triggers one stage still works.
	if config.AutoFindMinimalProto {
		objectJson = handleAutoDetect(data, packetId, fromServer, timestamp)
		buildPacketToSend(data, fromServer, timestamp, packetId, objectJson)
		if packetCounter%reportEvery == 0 && packetCounter > 0 {
			logAutoDetectSummary()
		}
		return
	}

	xorPad := pickPad(body)

	if packetId == playerGetTokenScRspId {
		xorDecrypt(data, xorPad)
		data, objectJson = PlayerGetTokenScRspPacket(data, packetId, objectJson)
	} else if packetId == playerGetTokenCsReqId {
		xorDecrypt(data, xorPad)
		data, objectJson = PlayerGetTokenCsReqPacket(data, packetId, timestamp, objectJson)
	} else {
		clone := append([]byte(nil), body...)
		xorDecrypt(clone, xorPad)

		usePcktId := packetId
		_, err := parseProto(packetId, clone)
		if errors.Is(err, ErrProtoNotFound) {
			_, err = parseProto(0, clone) // "0": "Unk" in packet ids.
			usePcktId = 0
		}
		if err != nil {
			log.Println("Cracking seed...", sentMs)
			seed := sentMs
			foundSeed, foundPad := bruteforce(seed, serverSeed, body, usePcktId)
			if foundSeed == 0 || foundPad == nil {
				log.Println("Could not bruteforce, skipping...")
			} else {
				sessionKey = foundPad
				xorPad = foundPad
			}
		}
		xorDecrypt(data, xorPad)
		objectJson = parseProtoToInterface(packetId, data)
	}

	buildPacketToSend(data, fromServer, timestamp, packetId, objectJson)
}

// pickPad returns the negotiated session key if we have one, otherwise a shipped
// key. Shipped keys are tried newest first and the one that yields a decodable
// message wins.
func pickPad(body []byte) []byte {
	if sessionKey != nil {
		return sessionKey
	}
	if len(initialKeys) == 1 {
		return initialKeys[0]
	}
	// Cache the winner so it is tested once per capture, not per packet.
	if activeInitialKey != nil {
		return activeInitialKey
	}

	for i, k := range initialKeys {
		clone := append([]byte(nil), body...)
		xorDecrypt(clone, k)
		if parsesAsUnk(clone) {
			activeInitialKey = k
			log.Printf("Decrypting with initial key %s", initialKeyNames[i])
			return k
		}
	}
	// A short packet can fail to parse by chance, so fall back to the newest
	// rather than dropping the packet.
	log.Printf("No shipped key decoded this packet cleanly; assuming the newest (%s)",
		initialKeyNames[0])
	return initialKeys[0]
}

func PlayerGetTokenCsReqPacket(data []byte, packetId uint16, timestamp time.Time, objectJson interface{}) ([]byte, interface{}) {
	dMsg, err := parseProto(packetId, data)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenCsReq proto", err)
		closeHandle()
	}
	oj, err := dMsg.MarshalJSON()
	if err != nil {
		log.Println("Could not parse PlayerGetTokenCsReq proto", err)
		closeHandle()
	}
	err = json.Unmarshal(oj, &objectJson)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenCsReq proto", err)
		closeHandle()
	}
	sentMs = uint64(timestamp.UnixMilli())
	return data, objectJson
}

func PlayerGetTokenScRspPacket(data []byte, packetId uint16, objectJson interface{}) ([]byte, interface{}) {
	dMsg, err := parseProto(packetId, data)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenScRsp proto", err)
		closeHandle()
	}
	oj, err := dMsg.MarshalJSON()
	if err != nil {
		log.Println("Could not parse PlayerGetTokenScRsp proto", err)
		closeHandle()
	}
	err = json.Unmarshal(oj, &objectJson)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenScRsp proto", err)
		closeHandle()
	}
	seedStr := dMsg.GetFieldByName("server_rand_key").(string)
	seed, err := base64.StdEncoding.DecodeString(seedStr)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenScRsp proto", err)
		closeHandle()
	}
	decrBytes, err := decrypt(privateKey, seed)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenScRsp proto", err)
		closeHandle()
	}
	decrSeed := binary.LittleEndian.Uint64(decrBytes)
	serverSeed = decrSeed
	log.Println("server seed:", serverSeed)

	return data, objectJson
}

func buildPacketToSend(data []byte, fromSever bool, timestamp time.Time, packetId uint16, objectJson interface{}) {
	packet := &Packet{
		Time:       timestamp.UnixMilli(),
		FromServer: fromSever,
		PacketId:   packetId,
		PacketName: GetProtoNameById(packetId),
		Object:     objectJson,
		Raw:        data,
	}

	jsonResult, err := json.Marshal(packet)
	if err != nil {
		log.Println("Json marshal error", err)
	}
	logPacket(packet)

	if GetProtoNameById(packetId) != "" && packetFilter[GetProtoNameById(packetId)] {
		return
	}
	sendStreamMsg(string(jsonResult))
}

func logPacket(packet *Packet) {
	from := "[Client]"
	if packet.FromServer {
		from = "[Server]"
	}
	forward := ""
	if strings.Contains(packet.PacketName, "Rsp") {
		forward = "<--"
	} else if strings.Contains(packet.PacketName, "Req") {
		forward = "-->"
	} else if strings.Contains(packet.PacketName, "Notify") && packet.FromServer {
		forward = "<-i"
	} else if strings.Contains(packet.PacketName, "Notify") {
		forward = "i->"
	}

	log.Println(color.GreenString(from),
		"\t",
		color.CyanString(forward),
		"\t",
		color.RedString(packet.PacketName),
		color.YellowString("#"+strconv.Itoa(int(packet.PacketId))),
		"\t",
		len(packet.Raw),
	)
}
