package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
)

func writeProto(protoName string, fields map[int32]string, additional string, prefix string) {
	str := "syntax = \"proto3\";\n\n" + prefix + "message " + protoName + " {\n"
	for _, tag := range sortedTags(fields) {
		str += "  " + fields[tag] + " = " + strconv.Itoa(int(tag)) + ";\n"
	}
	if additional != "" {
		str += additional + "\n"
	}
	str += "}\n"

	logHeader := "------------ " + protoName + ".proto" + " ------------"
	log.Println(logHeader)
	log.Println(str)
	log.Println(strings.Repeat("-", len(logHeader)))

	if err := os.MkdirAll("./out/", os.ModePerm); err != nil {
		log.Println("Error creating directory in writeProto:", err)
	}
	if err := os.WriteFile("./out/"+protoName+".proto", []byte(str), 0o644); err != nil {
		log.Println("Error writing file in writeProto:", err)
	}
}

func sortedTags(fields map[int32]string) []int32 {
	tags := make([]int32, 0, len(fields))
	for t := range fields {
		tags = append(tags, t)
	}
	for i := 1; i < len(tags); i++ {
		for j := i; j > 0 && tags[j] < tags[j-1]; j-- {
			tags[j], tags[j-1] = tags[j-1], tags[j]
		}
	}
	return tags
}

func writePacketIds(packetIds map[uint16]string) {
	if err := os.MkdirAll("./out/", os.ModePerm); err != nil {
		log.Println("Error creating directory in writePacketIds:", err)
	}
	data, err := json.Marshal(packetIds)
	if err != nil {
		log.Println("Error marshaling to JSON in writePacketIds:", err)
		return
	}
	if err := os.WriteFile("./out/packetIds.json", data, 0o644); err != nil {
		log.Println("Error writing to file in writePacketIds:", err)
	}
}

// stardbURL supplies the achievement ids. Ids are opaque integers on the wire so
// they cannot be recognised by shape, but the valid ones are known.
const stardbURL = "https://stardb.gg/api/zzz/achievements"

// achievementCatalogue is the id set, plus the arcade subset that tells the two
// achievement packets apart.
type achievementCatalogue struct {
	All    map[uint32]bool
	Arcade map[uint32]bool
}

// loadCatalogue fetches the ids, using ./data/stardb_achievements.json as a cache
// when it is under a week old, so a capture can be replayed offline. Failures
// are non-fatal: detection reports itself unavailable and the sniffer carries on.
func loadCatalogue() (*achievementCatalogue, error) {
	var raw []byte
	if st, err := os.Stat(catalogueCache); err == nil && time.Since(st.ModTime()) < 7*24*time.Hour {
		raw, _ = os.ReadFile(catalogueCache)
	} else {
		client := &http.Client{Timeout: 20 * time.Second}
		resp, err := client.Get(stardbURL)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", stardbURL, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch %s: HTTP %d", stardbURL, resp.StatusCode)
		}
		if raw, err = io.ReadAll(resp.Body); err != nil {
			return nil, err
		}
		if err := os.MkdirAll("./data", os.ModePerm); err == nil {
			os.WriteFile(catalogueCache, raw, 0o644)
		}
	}

	var rows []struct {
		ID     uint32 `json:"id"`
		Arcade bool   `json:"arcade"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("parse catalogue: %w", err)
	}
	if len(rows) == 0 {
		return nil, errors.New("catalogue is empty")
	}
	cat := &achievementCatalogue{
		All:    make(map[uint32]bool, len(rows)),
		Arcade: make(map[uint32]bool),
	}
	for _, r := range rows {
		cat.All[r.ID] = true
		if r.Arcade {
			cat.Arcade[r.ID] = true
		}
	}
	log.Printf("loaded %d achievement ids (%d arcade)", len(cat.All), len(cat.Arcade))
	return cat, nil
}

var catalogueCache = filepath.Join("./data", "stardb_achievements.json")

var errNoServerSeed = errors.New("no RSA-wrapped seed field found")

// unkPlayerGetTokenScRsp finds server_rand_key by RSA round-trip: a real blob
// decrypts to exactly 8 bytes, while the packet's other blob, sign, decrypts to
// 82. Exactly one packet in 140 matches.
func unkPlayerGetTokenScRsp(data []byte) (int32, uint64, error) {
	dMsg, err := parseUnkProto(data)
	if err != nil {
		return 0, 0, err
	}
	if privateKey == nil {
		return 0, 0, errors.New("no private key loaded")
	}

	// A real blob decrypts to exactly 8 bytes. Exactly one packet in 140 matches.
	var found int32
	var seed uint64
	hits := 0

	for _, tag := range dMsg.GetUnknownFields() {
		for _, f := range dMsg.GetUnknownField(tag) {
			if f.Encoding != proto.WireBytes {
				continue
			}
			blob, err := base64.StdEncoding.DecodeString(string(f.Contents))
			if err != nil {
				blob, err = base64.RawStdEncoding.DecodeString(string(f.Contents))
				if err != nil {
					continue
				}
			}
			plain, err := decrypt(privateKey, blob)
			if err != nil || len(plain) != 8 {
				continue
			}
			hits++
			if hits == 1 {
				found, seed = tag, leUint64(plain)
			}
		}
	}
	if hits != 1 {
		return 0, 0, fmt.Errorf("%w: %d fields decrypt to 8 bytes", errNoServerSeed, hits)
	}
	return found, seed, nil
}

func leUint64(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// Constraints on what may be called an achievement list. Swept across every
// response in two 3.2.0 captures these admit exactly the two real packets.
//
// The ratio is strict on purpose: a 37-entry list matched at 81% and a 117-entry
// one at 97%, so below-certainty is not evidence. The cost is that a patch adding
// achievements before stardb updates stops detection rather than returning a
// partial answer, which is the safer failure.
const (
	minAchievementEntries = 40
	// Constants in the descriptor table are all small; unconstrained voting
	// returns arbitrary large ones such as 10773171, which are always spurious.
	maxXorKey      = 1 << 16
	maxDetectDepth = 6
)

type achievementList struct {
	// Path is the chain of tags from the packet root to the repeated field's parent.
	Path    []int32
	ListTag int32
	Entries int
	IDTag   int32
	XORKey  uint64
	IDs     []uint32
	// Arcade is true when every id is an arcade id, which separates the two packets.
	Arcade bool
	// Matched counts ids that resolved to a catalogue entry. Detection requires
	// it to equal Entries: a 37-entry list matched at 81% and a 117-entry one at
	// 97%, so anything below certainty is not evidence. The cost is that a patch
	// adding achievements before stardb updates stops detection rather than
	// returning a partial answer, which is the safer failure.
	Matched int
}

var errNoAchievements = errors.New("no achievement list found")

// PathString renders the tag chain for logs, e.g. "f15.f1067.f10".
func (d *achievementList) PathString() string {
	s := ""
	for _, tag := range d.Path {
		s += "f" + strconv.Itoa(int(tag)) + "."
	}
	return s + "f" + strconv.Itoa(int(d.ListTag))
}

// unkAchievementList searches an unknown message for an achievement list. Both
// ZZZ lists are repeated submessages inside a larger response, the regular one
// three levels down (GetMiscDataScRsp.15 -> 1067 -> 10). The walk descends
// through single occurrences too, so the deep one is reached.
func unkAchievementList(data []byte, cat *achievementCatalogue) (*achievementList, error) {
	var best *achievementList

	var walk func(body []byte, path []int32, depth int)
	walk = func(body []byte, path []int32, depth int) {
		if depth > maxDetectDepth {
			return
		}
		dMsg, err := parseUnkProto(body)
		if err != nil {
			return
		}

		// Group the length-delimited fields by tag so repeats are seen together.
		subs := map[int32][][]byte{}
		for _, tag := range dMsg.GetUnknownFields() {
			for _, f := range dMsg.GetUnknownField(tag) {
				if f.Encoding == proto.WireBytes {
					subs[tag] = append(subs[tag], f.Contents)
				}
			}
		}

		for tag, bodies := range subs {
			if len(bodies) >= minAchievementEntries {
				if cand := checkAchievementList(bodies, cat); cand != nil {
					cand.ListTag = tag
					cand.Path = append([]int32(nil), path...)
					if best == nil || betterList(cand, best) {
						best = cand
					}
				}
			}
			for _, sub := range bodies {
				walk(sub, append(path, tag), depth+1)
			}
		}
	}

	walk(data, nil, 0)
	if best == nil {
		return nil, errNoAchievements
	}
	return best, nil
}

func betterList(a, b *achievementList) bool {
	if a.Matched != b.Matched {
		return a.Matched > b.Matched
	}
	return a.Entries > b.Entries
}

func checkAchievementList(elems [][]byte, cat *achievementCatalogue) *achievementList {
	vals := map[int32][]uint64{}
	for _, e := range elems {
		dMsg, err := parseUnkProto(e)
		if err != nil {
			return nil
		}
		for _, tag := range dMsg.GetUnknownFields() {
			for _, f := range dMsg.GetUnknownField(tag) {
				if f.Encoding == proto.WireVarint {
					vals[tag] = append(vals[tag], f.Value)
				}
			}
		}
	}

	var best *achievementList
	for tag, observed := range vals {
		if len(observed) < minAchievementEntries {
			continue
		}
		key, matched := bestXorKey(observed, cat.All)
		if matched < len(observed) || key >= maxXorKey {
			continue
		}

		ids := make([]uint32, len(observed))
		seen := make(map[uint32]bool, len(observed))
		allArcade := true
		for i, v := range observed {
			id := uint32(v ^ key)
			ids[i] = id
			seen[id] = true
			if !cat.Arcade[id] {
				allArcade = false
			}
		}
		// Ids are unique. This is what rejects the largest false positive: a
		// 104-entry list matched only 19 distinct ids, so it passed on count.
		if len(seen) != len(ids) {
			continue
		}

		cand := &achievementList{
			Entries: len(elems),
			IDTag:   tag,
			XORKey:  key,
			IDs:     ids,
			Arcade:  allArcade,
			Matched: matched,
		}
		if best == nil || betterList(cand, best) {
			best = cand
		}
	}
	return best
}

// bestXorKey recovers the constant applied to a set of observed values.
//
// Vote rather than search the 32-bit space: every (observed, catalogue) pair
// implies one candidate key, so the true key collects a vote per entry. Candidates
// are then scored on actual matches rather than votes, because the catalogue is
// dense enough to give low-bit keys spurious votes -- key 4 matches 57 of 65
// entries while key 0 matches all 65.
func bestXorKey(observed []uint64, idset map[uint32]bool) (uint64, int) {
	votes := map[uint64]int{}
	for _, v := range observed {
		for id := range idset {
			votes[v^uint64(id)]++
		}
	}

	var bestKey uint64
	bestGood, bestDistinct := -1, -1
	for key := range votes {
		good := 0
		seen := map[uint32]bool{}
		for _, v := range observed {
			if idset[uint32(v^key)] {
				good++
				seen[uint32(v^key)] = true
			}
		}
		if good > bestGood || (good == bestGood && len(seen) > bestDistinct) {
			bestKey, bestGood, bestDistinct = key, good, len(seen)
		}
	}
	return bestKey, bestGood
}

// Generated names. Even the leaf names are ours; neither message appears in the
// upstream descriptor table, so read them as labels, not identifiers.

// The two known element schemas. Even these names are ours; neither message
// appears in the upstream descriptor table, so read them as labels.
var (
	regularElem, regularHolder = "AchievementInfo", "AchievementData"
	arcadeElem, arcadeHolder   = "ArcadeAchievementInfo", "ArcadeAchievementData"
)

// idDecl renders the id field, carrying any recovered constant as a comment so
// xorfields keeps working on the generated output.
func idDecl(key uint64) string {
	if key != 0 {
		return fmt.Sprintf("// xor: %d\n  uint32 id", key)
	}
	return "uint32 id"
}

func writeAchievementProtos(list *achievementList) string {
	elem, holder, outer := regularElem, regularHolder, "GetMiscDataScRsp"
	fields := map[int32]string{
		list.IDTag: idDecl(list.XORKey),
		2:          "uint32 progress",
		3:          "int64 unlock_time",
		4:          "bool finished",
	}
	if list.Arcade {
		elem, holder, outer = arcadeElem, arcadeHolder, "GetArcadeAchievementDataScRsp"
		fields = map[int32]string{
			list.IDTag: idDecl(list.XORKey),
			2:          "uint32 group_id",
			9:          "bool unlocked",
			14:         "uint32 progress",
			15:         "uint32 completed",
		}
	}

	writeProto(elem, fields, "", "")
	writeProto(holder, map[int32]string{list.ListTag: "repeated " + elem + " list"}, "",
		"import \""+elem+".proto\";\n\n")

	if len(list.Path) == 0 {
		writeProto(outer, map[int32]string{list.ListTag: "repeated " + elem + " list"}, "",
			"import \""+elem+".proto\";\n\n")
		return outer
	}

	// Wrap from the inside out; Path is root-first.
	inner := holder
	for depth := len(list.Path) - 1; depth >= 1; depth-- {
		wrapper := "AchievementWrapper" + strconv.Itoa(depth)
		writeProto(wrapper, map[int32]string{list.Path[depth]: inner + " field"}, "",
			"import \""+inner+".proto\";\n\n")
		inner = wrapper
	}
	writeProto(outer, map[int32]string{list.Path[0]: inner + " field"}, "",
		"import \""+inner+".proto\";\n\n")
	return outer
}

type packetSet [][]byte

func (s packetSet) validWith(pad []byte) bool {
	ok := 0
	for _, p := range s {
		clone := append([]byte(nil), p...)
		xorDecrypt(clone, pad)
		if parsesAsUnk(clone) {
			ok++
		}
	}
	return ok >= minQuorum(len(s))
}

func minQuorum(n int) int {
	if n <= 3 {
		return n
	}
	return n - 2
}

func (s packetSet) strongest() []byte {
	var best []byte
	for _, p := range s {
		if len(p) > len(best) {
			best = p
		}
	}
	return best
}

// parsesAsUnk reports whether buf is a valid protobuf message.
func parsesAsUnk(buf []byte) bool {
	_, err := parseUnkProto(buf)
	return err == nil
}
