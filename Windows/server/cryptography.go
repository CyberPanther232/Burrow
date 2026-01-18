package main

import (
	"encoding/binary"
	"fmt"
	"io"
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

func sendFramed(conn net.Conn, data []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	_, err := conn.Write(lenBuf)
	if err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}

func readFramed(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	_, err := io.ReadFull(conn, lenBuf)
	if err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	data := make([]byte, length)
	_, err = io.ReadFull(conn, data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func runServerHandshake(conn net.Conn, serverKey noise.DHKey) (*noise.CipherState, *noise.CipherState, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Random:        nil,
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		StaticKeypair: serverKey,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create handshake state: %w", err)
	}

	// 1. Read the client's first message (e)
	msg, err := readFramed(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read handshake message 1: %w", err)
	}
	log.Printf("Received handshake message 1 from client: %d bytes\n", len(msg))
	_, _, _, err = hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to process handshake message 1: %w", err)
	}

	// 2. Write the second message (e, ee, s, es)
	msg, _, _, err = hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to write handshake message 2: %w", err)
	}
	log.Printf("Sending handshake message 2 to client: %d bytes\n", len(msg))
	err = sendFramed(conn, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send handshake message 2: %w", err)
	}

	// 3. Read the third message (s, se)
	msg, err = readFramed(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read handshake message 3: %w", err)
	}
	log.Printf("Received handshake message 3 from client: %d bytes\n", len(msg))
	_, sendCipher, recvCipher, err := hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to process handshake message 3: %w", err)
	}

	return sendCipher, recvCipher, nil
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
