# Burrow VPN

## Project Status

This project currently implements a basic VPN solution for **Windows** platforms, featuring a client and a server component. The core functionality, including the establishment of a TUN interface, UDP communication, and secure packet exchange using the Noise Protocol Framework (specifically the IK handshake pattern with AESGCM cipher), has been implemented and tested.

All known bugs related to packet encoding/decoding, server panics, and cryptographic handshake failures have been addressed. The client and server are designed to communicate securely, with the server persisting its identity key to ensure consistent connections across restarts.

### Key Features:
*   **TUN Interface:** Creates a virtual network interface for packet interception.
*   **UDP Communication:** Utilizes UDP for efficient data transfer between client and server.
*   **Noise Protocol Framework:** Implements strong cryptographic security for authenticated and encrypted communication.
*   **Persistent Server Key:** The server automatically generates and persists its private key, maintaining a stable public key for client connections.

## How to Run

Both the client and server applications require **Administrator privileges** to function correctly due to the creation and configuration of network interfaces.

### Prerequisites:
*   Go (version 1.18 or newer recommended) installed and configured.

### Running the Server:

1.  Navigate to the server directory in your terminal:
    ```bash
    cd Windows\server
    ```
2.  Build the server executable:
    ```bash
    go build .
    ```
3.  Run the server executable **as Administrator**:
    ```bash
    .\server.exe
    ```
    Upon its first run, the server will generate a `server.key` file and display its public key. Ensure this public key is copied for use in the client configuration.

### Running the Client:

1.  **Update Client with Server Public Key:**
    *   Open `Windows\client\main.go`.
    *   Locate the `serverHexKey` variable and replace its value with the public key obtained from the server's output (e.g., `serverHexKey := "your_server_public_key_here"`).
2.  Navigate to the client directory in your terminal:
    ```bash
    cd Windows\client
    ```
3.  Build the client executable:
    ```bash
    go build .
    ```
4.  Run the client executable **as Administrator**:
    ```bash
    .\client.exe
    ```

## Future Plans

The immediate focus has been on establishing a stable and secure Windows build. In the future, there are plans to extend this project to support **Linux** platforms, providing a cross-platform VPN solution. This will involve adapting the TUN device handling and network configuration to Linux-specific APIs and tools.
