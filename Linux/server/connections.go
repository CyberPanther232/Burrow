package main

import (
	"log"
	"net"

	"github.com/flynn/noise"
	"golang.zx2c4.com/wireguard/tun"
)

// Linux/server/connections.go
// Connection handling functions for Linux server build
// Developer: CyberPanther232

func startListener(dev tun.Device, conn net.Conn, recvCipher *noise.CipherState) {
	for {
		ciphertext, err := readFramed(conn)
		if err != nil {
			log.Printf("Listener: Error reading from TCP: %v", err)
			return
		}
		log.Printf("Listener: Received %d bytes from %s\n", len(ciphertext), conn.RemoteAddr().String())

		decryptedPacket, err := decryptPacket(recvCipher, ciphertext)
		if err != nil {
			log.Fatalf("Listener: Failed to decrypt packet: %v", err)
		}
		log.Printf("Listener: Decrypted packet: %d bytes\n", len(decryptedPacket))

		// Prepend 4-byte header for Linux TUN
		header := []byte{0x00, 0x00, 0x08, 0x00}
		packetWithHeader := append(header, decryptedPacket...)

		_, err = dev.Write([][]byte{packetWithHeader}, 0)
		if err != nil {
			log.Printf("Listener: Error writing to TUN device: %v", err)
		}
	}
}

func handleConnections(dev tun.Device, conn net.Conn, sendCipher *noise.CipherState) {
	packets := make([][]byte, 1)
	packets[0] = make([]byte, 1500) // Standard MTU size
	sizes := make([]int, 1)

	for {
		n, err := dev.Read(packets, sizes, 0)
		if err != nil {
			log.Printf("Handler: Read error: %v\n", err)
			break
		}

		for i := 0; i < n; i++ {
			packetData := packets[i][:sizes[i]]
			log.Printf("Handler: Captured packet: %d bytes\n", len(packetData))

			encryptedPacket := encryptPacket(sendCipher, packetData)
			log.Printf("Handler: Encrypted packet: %d bytes\n", len(encryptedPacket))

			err = sendFramed(conn, encryptedPacket)
			if err != nil {
				log.Printf("Handler: Failed to write to TCP: %v", err)
			}
		}
	}
}
