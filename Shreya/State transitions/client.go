package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
)

func main() {
	filePath := flag.String("file", "testfile.bin", "Path to the file")
	chunkIndex := flag.Uint64("index", 0, "Chunk index needed")
	flag.Parse()

	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	fmt.Println("Connection Successfull!")

	// STATE 1: Send 0x01
	nonce := NonceGenerate()
	packet01 := RequestPacket(*chunkIndex, nonce)
	fmt.Printf("Sending 0x01 of %d bytes\n", len(packet01))

	n, err := conn.Write(packet01)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Wrote %d bytes\n", n)

	// STATE 2: Receive 0x02
	typeBuf := make([]byte, 1)
	fmt.Println(" Waiting for response...")
	n, err = io.ReadFull(conn, typeBuf)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf(" Received type: 0x%02x\n", typeBuf[0])

	if typeBuf[0] != 0x02 {
		fmt.Printf("Expected 0x02, got %x\n", typeBuf[0])
		return
	}

	// Read the 4-byte ciphertext length
	lenBuf := make([]byte, 4)
	_, err = io.ReadFull(conn, lenBuf)
	if err != nil {
		fmt.Println(err)
		return
	}
	cipherLen := binary.BigEndian.Uint32(lenBuf)
	fmt.Printf(" Expecting ciphertext of %d bytes\n", cipherLen)

	// Read the ciphertext
	ciphertext := make([]byte, cipherLen)
	_, err = io.ReadFull(conn, ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Read the 32-byte H_resp
	var hResp [32]byte
	_, err = io.ReadFull(conn, hResp[:])
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(hResp)

	// STATE 3: Send 0x03 (LotteryTicket Signal)
	// Send the 1-byte packet using your updated PaymentPacket()
	packet03 := PaymentPacket()
	_, err = conn.Write(packet03)
	if err != nil {
		fmt.Println(err)
		return
	}

	// STATE 4: Receive 0x04 (KeyReveal)
	_, err = io.ReadFull(conn, typeBuf)
	if err != nil {
		fmt.Println(err)
		return
	}
	if typeBuf[0] != 0x04 {
		fmt.Printf(" Expected 0x04, got %x\n", typeBuf[0])
		return
	}

	var key [32]byte
	_, err = io.ReadFull(conn, key[:])
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf(" Received Key: %x\n", key)

	// -STATE 5: Verify and Decrypt
	// 5.1 Verify H_resp matches Keccak256(key)
	computedHash := Keccak256(key[:])
	if !bytes.Equal(computedHash[:], hResp[:]) {
		fmt.Println("Provider cheated!")
		return
	}
	fmt.Println(" Key is authentic.")

	// 5.2 Decrypt the chunk
	decryptedChunk, err := Decryption(key, ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Decrypted chunk of %d bytes\n", len(decryptedChunk))

	// 5.3 Load the original chunk from the file (using the -file flag)
	originalChunk, err := GetChunk(*filePath, *chunkIndex)
	if err != nil {
		fmt.Println("Failed to load original chunk:", err)
		return
	}

	// 5.4 Compare them
	if !bytes.Equal(decryptedChunk, originalChunk) {
		fmt.Println(" ERROR: Decrypted data does not match original!")
		return
	}

	fmt.Println("SUCCESS! Decrypted chunk matches original!")
	fmt.Println("[Client] Fair exchange complete!")
}
