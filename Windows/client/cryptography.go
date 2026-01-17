package main

import (
	"log"
	"net"

	"github.com/flynn/noise"
)

// Windows/client/cryptography.go
// Cryptography functions for Windows client build
// Developer: CyberPanther232

var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

func generateIdentity() (noise.DHKey, error) {
	return suite.GenerateKeypair(nil)
}

func runClientHandshake(conn *net.UDPConn, clientKey noise.DHKey, serverPubKey []byte) (*noise.CipherState, *noise.CipherState) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Random:        nil,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		StaticKeypair: clientKey,
		PeerStatic:    serverPubKey,
	})
	if err != nil {
		log.Fatalf("Failed to create handshake state: %v", err)
	}

	// 1. Send the first message to the server
	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		log.Fatalf("Failed to write handshake message: %v", err)
	}
	log.Printf("Sending handshake message to server: %d bytes\n", len(msg))
	_, err = conn.Write(msg)
	if err != nil {
		log.Fatalf("Failed to write to UDP: %v", err)
	}

	// 2. Read the server's response
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		log.Fatalf("Failed to read from UDP: %v", err)
	}
	log.Printf("Received handshake message from server: %d bytes\n", n)

	// 3. Process the server's response
	_, sendCipher, recvCipher, err := hs.ReadMessage(nil, resp[:n])
	if err != nil {
		log.Fatalf("Failed to read handshake message: %v", err)
	}

	return sendCipher, recvCipher
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
