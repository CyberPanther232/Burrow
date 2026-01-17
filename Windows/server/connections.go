package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"net"

	"github.com/flynn/noise"
	"golang.zx2c4.com/wireguard/tun"
)

// Windows/server/connections.go
// Connection handling functions for Windows server build
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

func startListener(dev tun.Device, conn *net.UDPConn, clientAddrChan chan<- *net.UDPAddr, recvCipher *noise.CipherState) {
	buffer := make([]byte, 2048)

	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading from UDP: %v", err)
			continue
		}
		fmt.Printf("Received %d bytes from %s\n", n, clientAddr.String())

		// Non-blocking send of client address
		select {
		case clientAddrChan <- clientAddr:
		default:
		}

		decryptedPacket, err := decryptPacket(recvCipher, buffer[:n])
		if err != nil {
			log.Printf("Failed to decrypt packet: %v", err)
			continue
		}

		decodedPacket, err := decodePacket(decryptedPacket)
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

func handleConnections(dev tun.Device, conn *net.UDPConn, clientAddrChan <-chan *net.UDPAddr, sendCipher *noise.CipherState) {
	var clientAddr *net.UDPAddr

	// 1. Create a "batch" of buffers.
	packets := make([][]byte, 1)
	packets[0] = make([]byte, 1500) // Standard MTU size

	// 2. Create a slice to store the sizes of the packets read
	sizes := make([]int, 1)

	for {
		// The 'want' from your error: ([][]byte, []int, int)
		// offset is usually 0 unless you're leaving space for headers
		n, err := dev.Read(packets, sizes, 0)
		if err != nil {
			fmt.Printf("Read error: %v\n", err)
			break
		}

		// Check for new client address
		select {
		case clientAddr = <-clientAddrChan:
			log.Printf("Client address updated to: %s", clientAddr.String())
		default:
		}

		if clientAddr == nil {
			continue // No client to send to yet
		}

		// n is the number of packets read in this batch
		for i := 0; i < n; i++ {
			packetData := packets[i][:sizes[i]]
			fmt.Printf("Captured packet: %d bytes\n", len(packetData))

			encodedPacket, err := encodePacket(packetData)
			if err != nil {
				log.Printf("Failed to encode packet: %v", err)
				continue
			}

			encryptedPacket := encryptPacket(sendCipher, encodedPacket)

			_, err = conn.WriteToUDP(encryptedPacket, clientAddr)
			if err != nil {
				log.Printf("Failed to write to UDP: %v", err)
			}
		}
	}
}
