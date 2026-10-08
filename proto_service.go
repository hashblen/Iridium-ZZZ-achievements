package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoparse"
	"github.com/jhump/protoreflect/dynamic"
)

var msgMap = make(map[string]*desc.MessageDescriptor)
var packetIdMap map[uint16]string
var packetNameMap = make(map[string]uint16)
var protoParser = protoparse.Parser{}

// InitProto loads whatever protos exist. In auto-detect mode there is nothing to
// load up front: the protos are deduced at runtime and written to ./out/.
func InitProto() {
	if config != nil && config.AutoFindMinimalProto {
		InitProtoAutoDetect()
		return
	}

	packetIdFile, _ := os.ReadFile("./data/packetIds.json")
	err := json.Unmarshal(packetIdFile, &packetIdMap)
	if err != nil {
		log.Fatalln("Could not load ./data/packetIds.json", err)
	}

	for k, v := range packetIdMap {
		packetNameMap[v] = k
	}

	protoParser.ImportPaths = []string{"./data/proto/"}
	for _, v := range packetIdMap {
		LoadProto(v)
	}

	buildXorTable()
}

// InitProtoAutoDetect loads just enough to parse unknown bytes. The empty Unk
// message is the whole point: everything lands in its unknown fields, which is
// what the detector walks and the brute forcer validates against.
func InitProtoAutoDetect() {
	packetIdMap = map[uint16]string{}
	protoParser.ImportPaths = []string{"./data/proto/", "./out/", "./data/"}

	// Unk.proto ships in data/, but write it if the folder is bare.
	if _, err := os.Stat("./data/Unk.proto"); os.IsNotExist(err) {
		if err := os.WriteFile("./data/Unk.proto", unkProtoSource, 0o644); err != nil {
			log.Fatalln("Could not prepare the Unk proto:", err)
		}
	}
	LoadProto("Unk")

	// Reuse a previous run's protos instead of re-deriving them.
	if ids, err := os.ReadFile("./out/packetIds.json"); err == nil {
		if err := json.Unmarshal(ids, &packetIdMap); err != nil {
			log.Println("Could not parse ./out/packetIds.json:", err)
		}
		for k, v := range packetIdMap {
			packetNameMap[v] = k
			LoadProto(v)
		}
		log.Printf("Reusing %d proto(s) from a previous run", len(packetIdMap))
	}

	buildXorTable()
}

var unkProtoSource = []byte("syntax = \"proto3\";\n\nmessage Unk {\n}\n")

// buildXorTable loads `// xor: N` from whichever proto directories exist. In
// auto-detect mode ./out/ holds the deduced protos.
func buildXorTable() {
	total := 0
	for _, dir := range []string{"./data/proto/", "./out/"} {
		if n, err := loadXorTable(dir); err == nil {
			total += n
		}
	}
	log.Printf("Loaded %d xor constants (-xor is %v)", total, xorEnabled)
}

// LoadProto parses a .proto by name and registers every message in it, so nested
// types resolve by name.
func LoadProto(protoName string) {
	fileDesc, err := protoParser.ParseFiles(protoName + ".proto")
	if err != nil {
		log.Println("Could not load proto file", protoName, err)
		return
	}

	for _, msg := range fileDesc[0].GetMessageTypes() {
		msgMap[msg.GetName()] = msg
	}
	msgMap[protoName] = fileDesc[0].FindMessage(protoName)
}

func GetProtoById(id uint16) *desc.MessageDescriptor {
	protoName, ok := packetIdMap[id]
	if !ok {
		return nil
	}
	return msgMap[protoName]
}

func GetProtoNameById(id uint16) string {
	protoName, ok := packetIdMap[id]
	if !ok {
		return ""
	}
	return protoName
}

var ErrProtoNotFound = errors.New("proto for this id not found")

func parseProto(id uint16, data []byte) (*dynamic.Message, error) {
	msg := GetProtoById(id)
	if msg == nil {
		return nil, ErrProtoNotFound
	}
	dMsg := dynamic.NewMessage(msg)

	err := dMsg.Unmarshal(data)
	if err != nil {
		return dMsg, err
	}
	// Convert the game's obfuscated wire values back to plain ones. Must happen
	// after Unmarshal (which needs the encoded bytes to parse the structure at
	// all) and exactly once per message.
	applyXors(GetProtoNameById(id), dMsg)
	return dMsg, nil
}

func parseProtoToJson(id uint16, data []byte) string {
	dMsg, err := parseProto(id, data)
	if err != nil {
		return ""
	}

	marshalJSON, err := dMsg.MarshalJSON()
	if err != nil {
		return ""
	}

	return string(marshalJSON)
}

func parseProtoToInterface(id uint16, data []byte) *interface{} {
	object := parseProtoToJson(id, data)

	var result *interface{}
	err := json.Unmarshal([]byte(object), &result)
	if err != nil {
		return nil
	}

	return result
}

// parseUnkProto parses against the empty Unk message, putting every field in its
// unknown fields. A successful parse doubles as the brute forcer's oracle.
func parseUnkProto(data []byte) (*dynamic.Message, error) {
	msg := msgMap["Unk"]
	if msg == nil {
		return nil, errors.New("Unk proto not loaded")
	}
	dMsg := dynamic.NewMessage(msg)
	return dMsg, dMsg.Unmarshal(data)
}
