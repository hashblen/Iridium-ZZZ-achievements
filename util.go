package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"log"
)

func removeMagic(data []byte) []byte {
	cut := data[7]
	data = data[10+2:]           // Removes token + four byte magic
	data = data[0 : len(data)-4] // Removes four byte magic at the end
	data = data[cut:]
	return data
}

func getHeaderAndBody(data []byte) ([]byte, []byte) {
	cut := data[7]
	data = data[10+2:]           // Removes token + two byte magic
	data = data[0 : len(data)-4] // Removes two byte magic at the end
	if len(data) < int(cut) {
		return data, nil
	}
	header := data[:cut]
	data = data[cut:]
	return header, data
}

func removeHeaderForParse(data []byte) []byte {
	//cut := data[8]
	//data = removeMagic(data)
	//return data[cut:]
	if binary.BigEndian.Uint32(data[0:4]) != 0x01234567 || binary.BigEndian.Uint32(data[len(data)-4:]) != 0x89ABCDEF {
		log.Println("ERROR MAGIC IS WRONG")
		return nil
	}
	data = data[4+2 : len(data)-4] // Magic + cmdid
	head_len := binary.BigEndian.Uint16(data[0:2])
	body_len := binary.BigEndian.Uint32(data[2:6])
	data = data[6:]
	return data[head_len : uint32(head_len)+body_len]
}

func xorDecrypt(data []byte, key []byte) {
	// Guard: an empty key means the caller lost its pad (e.g. a failed
	// bruteforce). Without this, key[i%len(key)] divides by zero and panics,
	// taking the whole capture down. Leaving the data untouched is strictly
	// better than crashing.
	if len(key) == 0 {
		log.Println("xorDecrypt called with an empty key; leaving data unchanged")
		return
	}
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ key[i%len(key)]
	}
}

func reformData(data []byte) []byte {
	i := 0
	tokenSizeTotal := 0
	var messages [][]byte
	for i < len(data) {
		convId := data[i : i+4]
		remainingHeader := data[i+8 : i+28]
		contentLen := int(binary.LittleEndian.Uint32(data[i+24 : i+28]))
		content := data[i+28 : (i + 28 + contentLen)]

		formattedMessage := make([]byte, 24+contentLen)
		copy(formattedMessage, convId)
		copy(formattedMessage[4:], remainingHeader)
		copy(formattedMessage[24:], content)
		i += 28 + contentLen
		tokenSizeTotal += 4
		messages = append(messages, formattedMessage)
	}

	return bytes.Join(messages, []byte{})
}

func newKey(seed uint64) []byte {
	generator := MT19937_64_new()
	generator.Seed(seed)

	// Generate the key.
	btes := make([]byte, 0, 4096)
	for i := 0; i < 4096; i += 8 {
		btes = binary.BigEndian.AppendUint64(btes, generator.NextULong())
	}

	return btes
}

// deriveSeed reproduces the game's clock path bit-for-bit.
//
// The float arithmetic here is deliberate and must NOT be replaced with exact integer
// arithmetic (the old big.Int / magic-constant version). ticks is ~6.4e17, well past
// 2^53, so the game's CVTSI2SD rounds it to a multiple of 128 before the multiply; that
// rounding is part of the value we need to reproduce. Combined error is ~1.7e-05 s,
// and since ticks is always a multiple of 1e4 the true fraction is always a multiple of
// 0.001, so the truncation only ever flips on second-aligned ms -- where the exact
// result is always 1 lower than the game's.
func deriveSeed(ms uint64) int32 {
	ticks := (ms*10_000 + 621355968000000000) & 0x3FFF_FFFF_FFFF_FFFF // (ms*10_000 + netEpochTicks) & tickMask
	return int32(int64(float64(ticks) * 1e-7))
}

func guess(ms uint64, serverSeed uint64, depth int, data []byte, packetId uint16) (uint64, []byte) {
	computedSeed := deriveSeed(ms)

	generator := NewRandom(computedSeed)
	for i := 0; i < depth; i++ {
		clientSeedHigh := generator.NextInt()
		clientSeed := uint64(uint32(computedSeed)) | (uint64(clientSeedHigh) << 32)

		aSeed := clientSeed ^ serverSeed
		key := newKey(aSeed)

		clone := make([]byte, len(data))
		copy(clone, data)
		xorDecrypt(clone, key)
		_, err := parseProto(packetId, clone)
		if err != nil {
			continue
		}
		log.Println("Found encryption key seed:", aSeed, "at depth", i)
		return aSeed, key
	}
	return 0, nil
}

const searchWindowSeconds = 15

func bruteforce(ms uint64, serverSeed uint64, data []byte, packetId uint16) (uint64, []byte) {
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

		seed, key := guess(uint64(seconds)*1000, serverSeed, 1, data, packetId)
		if key != nil {
			log.Println("Found for second", seconds)
			return seed, key
		}
	}
	log.Println("Unable to find the encryption key seed.")
	return 0, nil
}

func decrypt(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	b, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	if err != nil {
		return nil, err
	}
	return b, nil
}
