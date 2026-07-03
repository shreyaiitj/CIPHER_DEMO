package main

import (
	"encoding/binary"
)

const NonceSize = 32
const KeySize = 32

// Creates the 1st state
func RequestPacket(index uint64, nonce [NonceSize]byte) []byte {
	buf := make([]byte, 41) //1+8+32
	buf[0] = 0x01           // to know this is 1st state
	//convert to BigEndian
	binary.BigEndian.PutUint64(buf[1:9], index)
	//to cpy the nonce
	copy(buf[9:41], nonce[:])
	return buf
}

// Creates the 2nd state
func ResponsePacket(ciphertext []byte, hResp [32]byte) []byte {
	textSize := uint32((len(ciphertext)))
	buf := make([]byte, 1+4+textSize+32)
	buf[0] = 0x02 // to know this is 2nd state

	//convert to BigEndian
	binary.BigEndian.PutUint32(buf[1:5], textSize)

	copy(buf[5:5+len(ciphertext)], ciphertext)
	copy(buf[5+len(ciphertext):], hResp[:])
	return buf
}

// Creates the 3rd packet
func PaymentPacket() []byte {
	return []byte{0x03}
}

//Creates the 4th state

func RevealPacket(key [KeySize]byte) []byte {
	// Create a byte slice of exactly 33 bytes, all initialized to zero.
	buf := make([]byte, 33) //1+32

	// Byte 0: Set the packet type to 0x04.
	buf[0] = 0x04
	copy(buf[1:33], key[:])

	// Return the fully packed byte slice, ready to be sent over the network.
	return buf
}
