package main

// Windows/server/main.go
// Main entry point for Windows server build
// Developer: CyberPanther232

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"os/exec"
	"os/signal"

	"golang.zx2c4.com/wireguard/tun"
)

func main() {

	fmt.Println("Starting Windows VPN Server...")

	config, err := loadServerConfig("server_config.yml")
	if err != nil {
		log.Fatalf("Failed to load server configuration: %v", err)
	}

	fmt.Println("Creating TUN interface...")
	dev, err := tun.CreateTUN("BurrowNet", 1500)
	if err != nil {
		log.Fatalf("Failed to create TUN device: %v", err)
	}
	defer dev.Close()

	// 1. Bring the interface up
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		"name=BurrowNet", "static", config.Address, "255.255.255.0", "none")
	cmd.Run()
	fmt.Println("VPN Interface is UP. Press Ctrl+C to stop.")

	listener, err := net.Listen("tcp", ":"+fmt.Sprint(config.Port))
	if err != nil {
		log.Fatalf("Failed to listen on TCP: %v", err)
	}
	defer listener.Close()

	log.Println("Waiting for a client to connect...")
	conn, err := listener.Accept()
	if err != nil {
		log.Fatalf("Failed to accept connection: %v", err)
	}
	defer conn.Close()
	log.Printf("Client connected from %s\n", conn.RemoteAddr())

	serverKey, err := loadKey()
	if err != nil {
		log.Println("No key file found, generating a new one...")
		serverKey, err = generateIdentity()
		if err != nil {
			log.Fatalf("Failed to generate server identity: %v", err)
		}
		err = saveKey(serverKey)
		if err != nil {
			log.Fatalf("Failed to save server key: %v", err)
		}
	}
	log.Printf("Server public key: %x\n", serverKey.Public)

	sendCipher, recvCipher, err := runServerHandshake(conn, serverKey)
	if err != nil {
		log.Fatalf("Handshake failed: %v", err)
	}

	go startListener(dev, conn, recvCipher)
	go handleConnections(dev, conn, sendCipher)

	// 3. Wait for a termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("Shutting down...")
}
