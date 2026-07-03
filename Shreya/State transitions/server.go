package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
)

func initiateConnection(conn net.Conn, filePath string) {
	defer conn.Close()
	fmt.Println("Connection successfull!")
	// tO READ THE PACKET TYPE
	typeBuff := make([]byte, 1)
	_, err := io.ReadFull(conn, typeBuff)
	if err != nil {
		fmt.Println(err)
		return
	}
	if typeBuff[0] != 0x01 {
		fmt.Printf("Expected 0x01, got %x. Invalid.\n", typeBuff[0])
		return
	}
	cont := make([]byte, 40)
	_, err = io.ReadFull(conn, cont)
	if err != nil {
		fmt.Println(err)
		return
	}
	index := binary.BigEndian.Uint64(cont[0:8])
	var nonce [32]byte
	copy(nonce[:], cont[8:40])

	//Get the indexed chunk
	data, err := GetChunk(filePath, index)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%d bytes\n", len(data))
	key := KeyGenerate()
	ciphertext, err := Encryption(key, data)
	if err != nil {
		fmt.Println(err)
		return
	}
	hResp := Keccak256(key[:])

	packet02 := ResponsePacket(ciphertext, hResp)
	_, err = conn.Write(packet02)
	if err != nil {
		fmt.Println(err)
		return
	}
	_, err = io.ReadFull(conn, typeBuff)
	if err != nil {
		fmt.Println(err)
		return
	}
	if typeBuff[0] != 0x03 {
		fmt.Printf("Expected 0x03, got %x.INVALID.\n", typeBuff[0])
		return
	}

	packet04 := RevealPacket(key)
	_, err = conn.Write(packet04)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func main() {
	filePath := flag.String("file", "testfile.bin", "Path to the file to serve chunks from")
	flag.Parse()

	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Server has been setup on port 8080")
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		go initiateConnection(conn, *filePath)
	}

}
