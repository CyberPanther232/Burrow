package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"net"

	"golang.zx2c4.com/wireguard/tun"
)

// Windows/client/connections.go
// Connection handling functions for Windows client build
// Developer: CyberPanther232

func encodePacket(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(data)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodePacket(data []byte) ([]byte, error) {
	var decodedData []byte
	decoder := gob.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&decodedData)
	if err != nil {
		return nil, err
	}
	return decodedData, nil
}

func startListener(dev tun.Device) {
	addr, err := net.ResolveUDPAddr("udp", ":51821")
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}

	defer conn.Close()

	buffer := make([]byte, 2048)

	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading from UDP: %v", err)
			continue
		}
		fmt.Printf("Received %d bytes from %s\n", n, clientAddr.String())

		decodedPacket, err := decodePacket(buffer[:n])
		if err != nil {
			log.Printf("Failed to decode packet: %v", err)
			continue
		}

		_, err = dev.Write([][]byte{decodedPacket}, 0)
		if err != nil {
			log.Printf("Error writing to TUN device: %v", err)
		}

		fmt.Printf("Packet Data: %x\n", decodedPacket)

	}

}
