package main

// The auto-detect path: achievements with no protos, no packetIds table and
// no known XOR constants. See unkutils.go for the detection itself and
// sniffer.go for where it is invoked.

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// State mirroring what the NG and SR builds keep.
var (
	packetCounter uint32

	catalogue *achievementCatalogue
	// catalogueErr so the fetch is attempted once per capture, not per packet.
	catalogueErr error

	foundPlayerGetTokenScRsp bool
	foundAchievementRegular  bool
	foundAchievementArcade   bool

	// tokenPacket is only claimed in packetIds once its seed has produced a
	// working session key.
	tokenPacket uint16

	deducedPacketIds = make(map[uint16]string)

	pendingBodies [][]byte
	pendingIds    []uint16

	// Three buffered packets make a wrong key acceptance negligible (~3e-09).
	maxPending = 8

	// The shortest packet worth using as an oracle. The login burst has several
	// 6-20 byte frames that are not protobufs and never decode however good the
	// key is, so they make a correct key look wrong; they are also the weakest
	// oracle (noise passes 1.9% at 8 bytes versus 0/8000 at 356).
	minOracleBytes = 64

	reportEvery uint32 = 25
)

// resetAutoDetect clears per-capture state.
func resetAutoDetect() {
	packetCounter = 0
	foundPlayerGetTokenScRsp = false
	foundAchievementRegular = false
	foundAchievementArcade = false
	tokenPacket = 0
	sentMs = 0
	serverSeed = 0
	sessionKey = nil
	detectedXor = map[string]map[string]uint64{}
	deducedPacketIds = make(map[uint16]string)
	pendingBodies = nil
	pendingIds = nil
	activeInitialKey = nil
}

func getCatalogue() *achievementCatalogue {
	if catalogue != nil || catalogueErr != nil {
		return catalogue
	}
	cat, err := loadCatalogue()
	if err != nil {
		catalogueErr = err
		log.Println("Achievement auto-detection unavailable:", err)
		log.Println("Falling back to whatever protos are already loaded.")
		return nil
	}
	catalogue = cat
	return cat
}

// handleAutoDetect decrypts one packet as far as it can.
//
// Three stages, each skippable so a partial capture still yields what it can:
// find the RSA-wrapped seed, brute-force the session key, then locate the
// achievement lists. Only the last needs the network.
func handleAutoDetect(body []byte, packetId uint16, fromServer bool, timestamp time.Time) interface{} {
	packetCounter++

	// The request's timestamp seeds the key search. The response follows within
	// ~400ms and the search covers +/-15s, so either would work.
	if !fromServer && packetCounter <= 2 {
		sentMs = uint64(timestamp.UnixMilli())
	}

	xorPad := pickPad(body)
	if xorPad == nil {
		return nil
	}
	decrypted := append([]byte(nil), body...)
	xorDecrypt(decrypted, xorPad)

	// Stage 1: login. Only server packets qualify: the request carries an
	// RSA-wrapped blob too, but with the client's key.
	if !foundPlayerGetTokenScRsp && sessionKey == nil && fromServer {
		if _, seed, err := unkPlayerGetTokenScRsp(decrypted); err == nil {
			foundPlayerGetTokenScRsp = true
			serverSeed = seed
			tokenPacket = packetId
			log.Printf("Detected PlayerGetTokenScRsp in packet #%d, server seed %d",
				packetId, seed)
		}
	}

	// Stage 3: checked on every packet -- the regular list arrives in the login
	// burst and the arcade one only when the player opens arcade mode.
	if cat := getCatalogue(); cat != nil {
		if !foundAchievementRegular || !foundAchievementArcade {
			tryDetectAchievements(decrypted, packetId, cat)
		}
	}

	// Stage 2: only once we have a seed, and only when the packet does not
	// already decode.
	//
	// The oracle buffers the RAW body, not the copy already XOR'd with the
	// initial key. Applying a candidate pad on top of a stripped body leaves the
	// initial key in the XOR, so nothing ever validates.
	if foundPlayerGetTokenScRsp && sessionKey == nil && sentMs != 0 &&
		len(body) >= minOracleBytes && !parsesAsUnk(decrypted) {
		pendingBodies = append(pendingBodies, append([]byte(nil), body...))
		pendingIds = append(pendingIds, packetId)
		if len(pendingBodies) > maxPending {
			pendingBodies = pendingBodies[len(pendingBodies)-maxPending:]
			pendingIds = pendingIds[len(pendingIds)-maxPending:]
		}
		set := packetSet(pendingBodies)
		if seed, pad := bruteforceUnk(sentMs, serverSeed, set); pad != nil {
			sessionKey = pad
			log.Printf("Recovered session key from seed %d", seed)
			deduce("PlayerGetTokenScRsp", tokenPacket)
			xorDecrypt(decrypted, pad)
			pendingBodies = nil
			pendingIds = nil
		} else if len(pendingBodies) >= maxPending {
			log.Printf("Key search still failing after %d packets (sizes %v)",
				len(pendingBodies), packetSizes(pendingBodies))
			pendingBodies = pendingBodies[:0]
			pendingIds = pendingIds[:0]
		}
	}

	return renderAutoDetect(packetId, decrypted)
}

func renderAutoDetect(packetId uint16, decrypted []byte) interface{} {
	if GetProtoById(packetId) != nil {
		return parseProtoToInterface(packetId, decrypted)
	}
	return parseProtoToInterface(0, decrypted)
}

func tryDetectAchievements(decrypted []byte, packetId uint16, cat *achievementCatalogue) {
	list, err := unkAchievementList(decrypted, cat)
	if err != nil {
		return
	}
	// A second hit of the same kind means this is not the one already recorded;
	// the login burst can repeat a response.
	if list.Arcade && foundAchievementArcade {
		return
	}
	if !list.Arcade && foundAchievementRegular {
		return
	}

	key := "plaintext"
	if list.XORKey != 0 {
		key = fmt.Sprintf("XOR %d", list.XORKey)
	}
	kind := "regular"
	if list.Arcade {
		kind = "arcade"
	}
	log.Printf("Detected %s achievement list in packet #%d: %s repeated x%d, "+
		"id field f%d %s, %d distinct ids",
		kind, packetId, list.PathString(), list.Entries, list.IDTag, key, len(list.IDs))

	name := writeAchievementProtos(list)
	LoadProto(name)
	deduce(name, packetId)

	// Register the key directly rather than relying on the `// xor:` comment,
	// which was read at startup before these protos existed. The frontend needs
	// the ids decoded regardless of -xor: a constant recovered from real traffic
	// is a different kind of knowledge from the upstream annotations.
	elemName := regularElem
	if list.Arcade {
		elemName = arcadeElem
	}
	if list.XORKey != 0 {
		forceXor(elemName, "id", list.XORKey)
	}

	if list.Arcade {
		foundAchievementArcade = true
	} else {
		foundAchievementRegular = true
	}
	writePacketIds(deducedPacketIds)
}

func deduce(name string, id uint16) {
	deducedPacketIds[id] = name
	packetIdMap[id] = name
	packetNameMap[name] = id
}

// packetSizes reports lengths for the key-search diagnostic; yn renders a bool.
func packetSizes(bodies [][]byte) []int {
	out := make([]int, len(bodies))
	for i, b := range bodies {
		out[i] = len(b)
	}
	return out
}

func yn(ok bool) string {
	if ok {
		return "yes"
	}
	return "no"
}

func bruteforceUnk(ms, srvSeed uint64, set packetSet) (uint64, []byte) {
	strongest := set.strongest()
	for _, cand := range candidatePads(ms, srvSeed) {
		// Screen on the longest packet first: it discards almost every candidate
		// for the cost of one parse.
		clone := append([]byte(nil), strongest...)
		xorDecrypt(clone, cand.pad)
		if !parsesAsUnk(clone) {
			continue
		}
		if !set.validWith(cand.pad) {
			continue
		}
		return cand.seed, cand.pad
	}
	log.Println("Unable to find the encryption key seed.")
	return 0, nil
}

type padCandidate struct {
	seed uint64
	pad  []byte
}

func candidatePads(ms, srvSeed uint64) []padCandidate {
	var out []padCandidate
	base := int64(ms / 1000)
	for i := int64(0); i <= searchWindowSeconds*2; i++ {
		delta := i / 2
		if i%2 != 0 {
			delta = -(i + 1) / 2
		}
		seconds := base + delta
		if seconds < 0 {
			continue
		}
		if seed, pad := guessPad(uint64(seconds)*1000, srvSeed); pad != nil {
			out = append(out, padCandidate{seed, pad})
		}
	}
	return out
}

// guessPad derives the key for one clock value, at depth 1 like bruteforce.
func guessPad(ms, srvSeed uint64) (uint64, []byte) {
	computedSeed := deriveSeed(ms)
	generator := NewRandom(computedSeed)
	clientSeedHigh := generator.NextInt()
	clientSeed := uint64(uint32(computedSeed)) | (uint64(clientSeedHigh) << 32)
	aSeed := clientSeed ^ srvSeed
	return aSeed, newKey(aSeed)
}

// logAutoDetectSummary so a run either shows the achievements or says plainly
// that it did not.
func logAutoDetectSummary() {
	log.Println("---- auto-detect summary ----")
	log.Printf("  %-32s %s", "PlayerGetTokenScRsp (login seed)", yn(foundPlayerGetTokenScRsp))
	log.Printf("  %-32s %s", "regular achievements", yn(foundAchievementRegular))
	log.Printf("  %-32s %s", "arcade achievements", yn(foundAchievementArcade))
	if len(deducedPacketIds) > 0 {
		b, _ := json.Marshal(deducedPacketIds)
		log.Printf("  deduced packet ids: %s", string(b))
	}
	log.Println("----------------------------")
}
