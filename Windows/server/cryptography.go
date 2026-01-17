package main

import (
	"fmt"
	"log"
	"net"

	"github.com/flynn/noise"
)

// Windows/server/cryptography.go
// Cryptography functions for Windows server build
// Developer: CyberPanther232

var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

func generateIdentity() (noise.DHKey, error) {
	return suite.GenerateKeypair(nil)
}

func runServerHandshake(conn *net.UDPConn, serverKey noise.DHKey) (*noise.CipherState, *noise.CipherState, *net.UDPAddr, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Random:        nil,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		StaticKeypair: serverKey,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create handshake state: %w", err)
	}

	// 1. Read the client's first message
	buf := make([]byte, 4096)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read from UDP: %w", err)
	}
	log.Printf("Received handshake message from client: %d bytes\n", n)

	// 2. Process the client's message
	_, _, _, err = hs.ReadMessage(nil, buf[:n])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read handshake message: %w", err)
	}

	// 3. Write the response back to the client
	res, sendCipher, recvCipher, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to write handshake message: %w", err)
	}
	log.Printf("Sending handshake message to client: %d bytes\n", len(res))
	_, err = conn.WriteToUDP(res, addr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to write to UDP: %w", err)
	}

	return sendCipher, recvCipher, addr, nil
}

func encryptPacket(cs *noise.CipherState, plaintext []byte) []byte {
	encryptedPacket, err := cs.Encrypt(nil, nil, plaintext)
	if err != nil {
		log.Fatalf("Failed to encrypt packet: %v", err)
	}
	return encryptedPacket
}

func decryptPacket(cs *noise.CipherState, ciphertext []byte) ([]byte, error) {
	decryptedPacket, err := cs.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return nil, err
	}
	return decryptedPacket, nil
}
