package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"net/netip"
	"strconv"
)

// How many addresses pick tries past the first before it gives up
const probes = 1024

// seed is what a sandbox hashes its addresses from: the uid and launcher name, so a launcher keeps its addresses
// across launches while they're free
func seed(uid int, name string) [32]byte {
	return sha256.Sum256([]byte("netns-netkit\x00" + strconv.Itoa(uid) + "\x00" + name))
}

// pick returns the address of block that seed hashes to, or the first after it (wrapping within the block) that taken
// doesn't refuse. Never the first or last address of the block
func pick(block netip.Prefix, seed [32]byte, taken func(netip.Addr) bool) (netip.Addr, error) {
	base := new(big.Int).SetBytes(block.Masked().Addr().AsSlice())
	bits := block.Addr().BitLen() - block.Bits()
	// The usable offsets, 1 to size-2
	size := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	size.Sub(size, big.NewInt(2))
	off := new(big.Int).Mod(new(big.Int).SetBytes(seed[:]), size)
	for range probes {
		n := new(big.Int).Add(base, new(big.Int).Add(off, big.NewInt(1)))
		buf := n.FillBytes(make([]byte, block.Addr().BitLen()/8))
		a, _ := netip.AddrFromSlice(buf)
		if !taken(a) {
			return a, nil
		}
		off.Add(off, big.NewInt(1)).Mod(off, size)
	}
	return netip.Addr{}, fmt.Errorf("No free address in %v", block)
}

// primaryName is the name of the netkit primary of the sandbox of launcher name of uid: the uid in base 36, so no two
// users share one, and a hash of the name, cut to the 15 bytes of a device name (7 hex digits or more for a uid below 36^3)
func primaryName(prefix string, uid int, name string) string {
	h := sha256.Sum256([]byte(name))
	n := fmt.Sprintf("%s%s-%x", prefix, strconv.FormatInt(int64(uid), 36), h)
	return n[:15]
}
