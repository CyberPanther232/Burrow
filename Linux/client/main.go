package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
)

func main() {
	// 1. Create the TUN interface
	dev, err := tun.CreateTUN("BurrowClient", 1500)
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()

	config, err := loadClientConfig("client_config.yml")
	if err != nil {
		log.Fatalf("Failed to load client configuration: %v", err)
	}

	// 2. Connect to the Server via TCP
	conn, err := net.Dial("tcp", config.ServerAddress+":"+fmt.Sprint(config.ServerPort))
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()
	log.Println("Connected to server")

	clientKey, err := generateIdentity()
	if err != nil {
		log.Fatalf("Failed to generate client key: %v", err)
	}

	sendCipher, recvCipher, err := runClientHandshake(conn, clientKey)
	if err != nil {
		log.Fatalf("Handshake failed: %v", err)
	}

	// 3. Bring the interface up
	cmd := exec.Command("ip", "addr", "add", "10.0.0.2/24", "dev", "BurrowClient")
	cmd.Run()
	cmd = exec.Command("ip", "link", "set", "dev", "BurrowClient", "up")
	cmd.Run()

	// 4. Start the Upstream Loop (TUN -> TCP)
	go func() {
		packets := make([][]byte, 1)
		packets[0] = make([]byte, 1500)
		sizes := make([]int, 1)
		for {
			n, err := dev.Read(packets, sizes, 0)
			if err != nil {
				log.Printf("Upstream: Error reading from TUN device: %v", err)
				continue
			}
			for i := 0; i < n; i++ {
				packetData := packets[i][:sizes[i]]
				if len(packetData) == 0 {
					continue
				}
				log.Printf("Upstream: Raw packet: %d bytes\n", len(packetData))

				encryptedPacket := encryptPacket(recvCipher, packetData)
				log.Printf("Upstream: Encrypted packet: %d bytes\n", len(encryptedPacket))

				err = sendFramed(conn, encryptedPacket)
				if err != nil {
					log.Printf("Upstream: Failed to write to TCP: %v", err)
				}
			}
		}
	}()

	// 5. Start the Downstream Loop (TCP -> TUN)
	go func() {
		for {
			ciphertext, err := readFramed(conn)
			if err != nil {
				log.Printf("Downstream: Error reading from TCP: %v", err)
				return
			}
			log.Printf("Downstream: Received %d bytes\n", len(ciphertext))

			decryptedPacket, err := decryptPacket(sendCipher, ciphertext)
			if err != nil {
				log.Fatalf("Downstream: Failed to decrypt packet: %v", err)
			}
			log.Printf("Downstream: Decrypted packet: %d bytes\n", len(decryptedPacket))

			// Prepend 4-byte header for Linux TUN
			header := []byte{0x00, 0x00, 0x08, 0x00}
			packetWithHeader := append(header, decryptedPacket...)

			// Write the data received from the server back into our local OS
			_, err = dev.Write([][]byte{packetWithHeader}, 4)
			if err != nil {
				log.Printf("Downstream: Error writing to TUN device: %v", err)
			}
		}
	}()

	// Keep alive until Ctrl+C
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}
