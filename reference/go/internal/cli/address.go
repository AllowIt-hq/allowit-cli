package cli

import (
	"encoding/base32"
	"encoding/binary"
	"math/big"
	"strings"
)

// Early, offline address checks so malformed input never reaches the network.
// The server repeats the same checks and remains authoritative.

func solanaAddress(s string) bool {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	if len(s) < 32 || len(s) > 44 {
		return false
	}
	n := new(big.Int)
	for _, c := range s {
		i := strings.IndexRune(alphabet, c)
		if i < 0 {
			return false
		}
		n.Mul(n, big.NewInt(58))
		n.Add(n, big.NewInt(int64(i)))
	}
	zeros := len(s) - len(strings.TrimLeft(s, "1"))
	return zeros+len(n.Bytes()) == 32
}

// stellarAddress validates a SEP-23 strkey: G (account), M (muxed) or C
// (contract); contractOnly accepts only C.
func stellarAddress(v string, contractOnly bool) bool {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	b, err := enc.DecodeString(v)
	if err != nil || (len(b) != 35 && len(b) != 43) || enc.EncodeToString(b) != v {
		return false
	}
	if !((len(b) == 35 && (b[0] == 16 || (!contractOnly && b[0] == 48))) || (!contractOnly && len(b) == 43 && b[0] == 96)) {
		return false
	}
	var crc uint16
	for _, octet := range b[:len(b)-2] {
		crc ^= uint16(octet) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return binary.LittleEndian.Uint16(b[len(b)-2:]) == crc
}

func railAddress(rail, address string, contract bool) bool {
	switch rail {
	case "stellar":
		return stellarAddress(address, contract)
	case "solana":
		return solanaAddress(address)
	}
	return false
}
