package main

import (
	"encoding/hex"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
)

func setupInterface(name string, ip string) error {
	// Example: netsh interface ip set address name="BurrowNet" static 10.0.0.2 255.255.255.0
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+name, "static", ip, "255.255.255.0", "none")

	return cmd.Run()
}

func main() {
	// 1. Create the TUN interface
	dev, err := tun.CreateTUN("BurrowClient", 1500)
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()

	// 2. Connect to the Server via UDP
	// Replace with your server's actual public IP and port
	serverAddr, _ := net.ResolveUDPAddr("udp", "10.0.0.1:51820")
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Fatal(err)
	}

	clientKey, err := generateIdentity()
	if err != nil {
		log.Fatalf("Failed to generate client key: %v", err)
	}

	// IMPORTANT: Replace with the server's actual public key
	serverHexKey := "35563bd99195169ec906e8611c829fddbecc4df7008f2c1dfd2f9eeea20cde20"
	serverPubKey, err := hex.DecodeString(serverHexKey)
	if err != nil {
		log.Fatalf("Failed to decode server public key: %v", err)
	}

	sendCipher, recvCipher := runClientHandshake(conn, clientKey, serverPubKey)

	// 3. Start the Upstream Loop (TUN -> UDP)
	go func() {
		packets := make([][]byte, 1)
		packets[0] = make([]byte, 1500)
		sizes := make([]int, 1)
		for {
			n, err := dev.Read(packets, sizes, 0)
			if err != nil {
				log.Printf("Error reading from TUN device: %v", err)
				continue
			}
			for i := 0; i < n; i++ {
				packetData := packets[i][:sizes[i]]
				if len(packetData) == 0 {
					continue
				}

				encodedPacket, err := encodePacket(packetData)
				if err != nil {
					log.Printf("Failed to encode packet: %v", err)
					continue
				}

				encryptedPacket := encryptPacket(sendCipher, encodedPacket)

				_, err = conn.Write(encryptedPacket)
				if err != nil {
					log.Printf("Failed to write to UDP: %v", err)
				}
			}
		}
	}()

	// 4. Start the Downstream Loop (UDP -> TUN)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Printf("Error reading from UDP: %v", err)
				continue
			}

			decryptedPacket, err := decryptPacket(recvCipher, buf[:n])
			if err != nil {
				log.Printf("Failed to decrypt packet: %v", err)
				continue
			}

			decodedPacket, err := decodePacket(decryptedPacket)
			if err != nil {
				log.Printf("Failed to decode packet: %v", err)
				continue
			}

			// Write the data received from the server back into our local OS
			_, err = dev.Write([][]byte{decodedPacket}, 0)
			if err != nil {
				log.Printf("Error writing to TUN device: %v", err)
			}
		}
	}()

	// Keep alive until Ctrl+C
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}
