// Written in 2012 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

// Package blake2b implements BLAKE2b cryptographic hash function.
package blake2b

import (
	"encoding/binary"
	"hash"
)

const (
	BlockSize  = 128 // block size of algorithm
	Size       = 64  // maximum digest size
	DSize      = 32
)

type digest struct {
	h  [8]uint64       // current chain value
	t  [2]uint64       // message bytes counter
	f  [2]uint64       // finalization flags
	x  [BlockSize]byte // buffer for data not yet compressed
	nx int             // number of bytes in buffer

	ih         [8]uint64       // initial chain value (after config)
	isLastNode bool            // indicates processing of the last node in tree hashing
}

// Initialization values.
var iv = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

// initialize initializes digest with the given
// config, which must be non-nil and verified.
func (d *digest) initialize() {
	var p [BlockSize]byte
	p[0] = DSize
	p[2] = 1
	p[3] = 1
	for i := 0; i < 8; i++ {
		d.h[i] = iv[i] ^ binary.LittleEndian.Uint64(p[i*8:])
	}

	// Save a copy of initialized state.
	copy(d.ih[:], d.h[:])
}

// New256 returns a new hash.Hash computing the BLAKE2b 32-byte checksum.
func New256() hash.Hash {
	d := new(digest)
	d.initialize()
	return d
}

// Reset resets the state of digest to the initial state
// after configuration and keying.
func (d *digest) Reset() {
	copy(d.h[:], d.ih[:])
	d.t[0] = 0
	d.t[1] = 0
	d.f[0] = 0
	d.f[1] = 0
	d.nx = 0
}

// Size returns the digest size in bytes.
func (d *digest) Size() int { return DSize }

// BlockSize returns the algorithm block size in bytes.
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	left := BlockSize - d.nx
	if len(p) > left {
		// Process buffer.
		copy(d.x[d.nx:], p[:left])
		p = p[left:]
		blocks(d, d.x[:])
		d.nx = 0
	}
	// Process full blocks except for the last one.
	if len(p) > BlockSize {
		n := len(p) &^ (BlockSize - 1)
		if n == len(p) {
			n -= BlockSize
		}
		blocks(d, p[:n])
		p = p[n:]
	}
	// Fill buffer.
	d.nx += copy(d.x[d.nx:], p)
	return
}

// Sum returns the calculated checksum.
func (d *digest) Sum(in []byte) []byte {
	hash := d.checkSum()
	return append(in, hash[:DSize]...)
}

func (d *digest) checkSum() [Size]byte {
	dec := BlockSize - uint64(d.nx)
	if d.t[0] < dec {
		d.t[1]--
	}
	d.t[0] -= dec

	// Pad buffer with zeros.
	for i := d.nx; i < len(d.x); i++ {
		d.x[i] = 0
	}
	// Set last block flag.
	d.f[0] = 0xffffffffffffffff
	if d.isLastNode {
		d.f[1] = 0xffffffffffffffff
	}
	// Compress last block.
	blocks(d, d.x[:])

	var out [Size]byte
	j := 0
	for _, s := range d.h[:(DSize-1)/8+1] {
		out[j+0] = byte(s >> 0)
		out[j+1] = byte(s >> 8)
		out[j+2] = byte(s >> 16)
		out[j+3] = byte(s >> 24)
		out[j+4] = byte(s >> 32)
		out[j+5] = byte(s >> 40)
		out[j+6] = byte(s >> 48)
		out[j+7] = byte(s >> 56)
		j += 8
	}
	return out
}

// Sum256 returns a 32-byte BLAKE2b hash of data.
func Sum256(data []byte) (out [32]byte) {
	var d digest
	d.initialize()
	d.Write(data)
	sum := d.checkSum()
	copy(out[:], sum[:32])
	return
}
