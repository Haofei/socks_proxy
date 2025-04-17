package main

import (
	"bufio"
	"encoding/binary"
	"errors" // Import errors package for EOF check if needed, though io.Copy handles it well
	"flag"
	"io"
	"log"
	"net"
	"strconv"
)

const (
	socks5Version       = 0x05
	methodNoAuth        = 0x00 // Not used in this server config, but defined
	methodUserPass      = 0x02
	noAcceptableMethods = 0xFF // Added for clarity
	userAuthVersion     = 0x01 // Version for username/password auth subnegotiation

	cmdConnect     = 0x01
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIPv6   = 0x04

	authSuccess         = 0x00
	authFailure         = 0x01
	replySuccess        = 0x00
	replyGeneralFailure = 0x01
	// Add other reply codes if needed (e.g., Command not supported, Host unreachable)
)

// Config holds the proxy configuration
type Config struct {
	Username string
	Password string
}

// handleConnection processes a single client connection
func handleConnection(conn net.Conn, config *Config) {
	defer conn.Close()
	log.Printf("Handling connection from %s", conn.RemoteAddr())

	reader := bufio.NewReader(conn)

	// 1. Client Greeting & Method Selection
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	ver, err := reader.ReadByte()
	if err != nil {
		log.Printf("Error reading version from %s: %v", conn.RemoteAddr(), err)
		return
	}
	if ver != socks5Version {
		log.Printf("Unsupported SOCKS version %d from %s", ver, conn.RemoteAddr())
		return
	}

	nMethods, err := reader.ReadByte()
	if err != nil {
		log.Printf("Error reading nMethods from %s: %v", conn.RemoteAddr(), err)
		return
	}

	methods := make([]byte, nMethods)
	_, err = io.ReadFull(reader, methods)
	if err != nil {
		log.Printf("Error reading methods from %s: %v", conn.RemoteAddr(), err)
		return
	}

	// Since this server *requires* Username/Password, check if the client supports it.
	clientSupportsUserPass := false
	for _, method := range methods {
		if method == methodUserPass {
			clientSupportsUserPass = true
			break
		}
	}

	// Server Response to Method Selection
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	var response []byte
	if !clientSupportsUserPass {
		log.Printf("Client %s does not support required auth method (User/Pass)", conn.RemoteAddr())
		response = []byte{socks5Version, noAcceptableMethods}
		_, writeErr := conn.Write(response)
		if writeErr != nil {
			log.Printf("Error writing unacceptable method response to %s: %v", conn.RemoteAddr(), writeErr)
		}
		return // Close connection
	}

	// Respond that we selected Username/Password authentication
	response = []byte{socks5Version, methodUserPass}
	_, err = conn.Write(response)
	if err != nil {
		log.Printf("Error writing method selection response to %s: %v", conn.RemoteAddr(), err)
		return
	}

	// 2. Username/Password Authentication
	if !handleAuth(reader, conn, config) {
		// handleAuth logs errors and sends failure response internally
		return
	}

	// 3. Client Request & Proxying
	if !handleRequest(reader, conn) {
		// handleRequest logs errors and sends failure reply internally if needed
		return
	}

	log.Printf("Connection from %s finished", conn.RemoteAddr())
}

// handleAuth processes username/password authentication subnegotiation
func handleAuth(reader *bufio.Reader, conn net.Conn, config *Config) bool {
	// +----+------+----------+------+----------+
	// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	// +----+------+----------+------+----------+
	// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	// +----+------+----------+------+----------+
	authVer, err := reader.ReadByte()
	if err != nil {
		log.Printf("Auth: Error reading auth version from %s: %v", conn.RemoteAddr(), err)
		// Don't send response here, connection likely broken
		return false
	}
	// Should be 0x01 for username/password auth
	if authVer != userAuthVersion {
		log.Printf("Auth: Unsupported auth version %d from %s", authVer, conn.RemoteAddr())
		// Send failure response
		_, writeErr := conn.Write([]byte{userAuthVersion, authFailure})
		if writeErr != nil {
			log.Printf("Auth: Error writing auth failure response to %s: %v", conn.RemoteAddr(), writeErr)
		}
		return false
	}

	ulen, err := reader.ReadByte()
	if err != nil {
		log.Printf("Auth: Error reading username length from %s: %v", conn.RemoteAddr(), err)
		return false
	}
	if ulen == 0 {
		log.Printf("Auth: Received zero length username from %s", conn.RemoteAddr())
		_, writeErr := conn.Write([]byte{userAuthVersion, authFailure})
		if writeErr != nil {
			log.Printf("Auth: Error writing auth failure response to %s: %v", conn.RemoteAddr(), writeErr)
		}
		return false
	}

	username := make([]byte, ulen)
	_, err = io.ReadFull(reader, username)
	if err != nil {
		log.Printf("Auth: Error reading username from %s: %v", conn.RemoteAddr(), err)
		return false
	}

	plen, err := reader.ReadByte()
	if err != nil {
		log.Printf("Auth: Error reading password length from %s: %v", conn.RemoteAddr(), err)
		return false
	}
	if plen == 0 {
		log.Printf("Auth: Received zero length password from %s", conn.RemoteAddr())
		_, writeErr := conn.Write([]byte{userAuthVersion, authFailure})
		if writeErr != nil {
			log.Printf("Auth: Error writing auth failure response to %s: %v", conn.RemoteAddr(), writeErr)
		}
		return false
	}

	password := make([]byte, plen)
	_, err = io.ReadFull(reader, password)
	if err != nil {
		log.Printf("Auth: Error reading password from %s: %v", conn.RemoteAddr(), err)
		return false
	}

	// Verify credentials
	// +----+--------+
	// |VER | STATUS |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	var status byte
	if string(username) == config.Username && string(password) == config.Password {
		log.Printf("Auth: Successful authentication for user '%s' from %s", config.Username, conn.RemoteAddr())
		status = authSuccess
	} else {
		log.Printf("Auth: Failed authentication for user '%s' from %s", string(username), conn.RemoteAddr())
		status = authFailure
	}

	_, err = conn.Write([]byte{userAuthVersion, status})
	if err != nil {
		log.Printf("Auth: Error writing auth status %d to %s: %v", status, conn.RemoteAddr(), err)
		return false // Can't proceed if write fails
	}

	return status == authSuccess
}

// handleRequest processes the client's connection request after successful authentication
func handleRequest(reader *bufio.Reader, conn net.Conn) bool {
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	// Read the fixed-size portion of the request header (VER, CMD, RSV, ATYP)
	reqHeader := make([]byte, 4)
	_, err := io.ReadFull(reader, reqHeader)
	if err != nil {
		log.Printf("Request: Error reading request header from %s: %v", conn.RemoteAddr(), err)
		// Don't send reply, connection likely broken
		return false
	}

	ver, cmd, atyp := reqHeader[0], reqHeader[1], reqHeader[3]

	if ver != socks5Version {
		log.Printf("Request: Unsupported SOCKS version %d in request from %s", ver, conn.RemoteAddr())
		sendReply(conn, replyGeneralFailure, nil) // Or a more specific error if available
		return false
	}

	if cmd != cmdConnect {
		log.Printf("Request: Unsupported command %d from %s", cmd, conn.RemoteAddr())
		sendReply(conn, replyGeneralFailure, nil) // SOCKS spec suggests "Command not supported" (0x07)
		return false
	}

	// Read DST.ADDR based on ATYP
	var dstAddr string
	switch atyp {
	case addrTypeIPv4:
		ipBytes := make([]byte, 4)
		_, err = io.ReadFull(reader, ipBytes)
		if err != nil {
			log.Printf("Request: Error reading IPv4 address from %s: %v", conn.RemoteAddr(), err)
			return false // Don't reply, conn broken
		}
		dstAddr = net.IP(ipBytes).String()
	case addrTypeDomain:
		addrLen, err := reader.ReadByte()
		if err != nil {
			log.Printf("Request: Error reading domain length from %s: %v", conn.RemoteAddr(), err)
			return false
		}
		domainBytes := make([]byte, addrLen)
		_, err = io.ReadFull(reader, domainBytes)
		if err != nil {
			log.Printf("Request: Error reading domain name from %s: %v", conn.RemoteAddr(), err)
			return false
		}
		dstAddr = string(domainBytes)
	case addrTypeIPv6:
		ipBytes := make([]byte, 16)
		_, err = io.ReadFull(reader, ipBytes)
		if err != nil {
			log.Printf("Request: Error reading IPv6 address from %s: %v", conn.RemoteAddr(), err)
			return false
		}
		dstAddr = net.IP(ipBytes).String()
	default:
		log.Printf("Request: Unsupported address type %d from %s", atyp, conn.RemoteAddr())
		sendReply(conn, replyGeneralFailure, nil) // SOCKS spec suggests "Address type not supported" (0x08)
		return false
	}

	// Read DST.PORT
	portBytes := make([]byte, 2)
	_, err = io.ReadFull(reader, portBytes)
	if err != nil {
		log.Printf("Request: Error reading port from %s: %v", conn.RemoteAddr(), err)
		return false
	}
	dstPort := binary.BigEndian.Uint16(portBytes)

	// Resolve domain name if necessary (net.Dial handles this)
	targetAddr := net.JoinHostPort(dstAddr, strconv.Itoa(int(dstPort)))
	log.Printf("Request: Client %s requesting connection to %s", conn.RemoteAddr(), targetAddr)

	// Connect to the destination
	dstConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Request: Failed to dial destination %s for client %s: %v", targetAddr, conn.RemoteAddr(), err)
		// Map net errors to SOCKS replies (e.g., connection refused, host unreachable)
		// For simplicity, using general failure here.
		sendReply(conn, replyGeneralFailure, nil)
		return false
	}
	defer dstConn.Close()
	log.Printf("Request: Connection established to %s for client %s (local bind: %s)", targetAddr, conn.RemoteAddr(), dstConn.LocalAddr())

	// Send success reply back to the client
	// The BND.ADDR and BND.PORT should be the address and port the server uses
	// to connect to the target host (dstConn.LocalAddr()).
	sendReply(conn, replySuccess, dstConn.LocalAddr())

	// Start proxying data
	log.Printf("Starting proxy data transfer between %s and %s", conn.RemoteAddr(), targetAddr)
	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(dstConn, conn)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			log.Printf("Error copying from client %s to target %s: %v", conn.RemoteAddr(), targetAddr, err)
		} else {
			// log.Printf("Copy client->target finished for %s", conn.RemoteAddr())
		}
		// Signal target connection to close write side if client closes read side
		if tcpConn, ok := dstConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		errChan <- err // Send nil on clean EOF
	}()

	go func() {
		_, err := io.Copy(conn, dstConn)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			log.Printf("Error copying from target %s to client %s: %v", targetAddr, conn.RemoteAddr(), err)
		} else {
			// log.Printf("Copy target->client finished for %s", conn.RemoteAddr())
		}
		// Signal client connection to close write side if target closes read side
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		errChan <- err // Send nil on clean EOF
	}()

	// Wait for both copy operations to complete
	<-errChan
	<-errChan

	log.Printf("Proxy data transfer finished for %s", conn.RemoteAddr())
	return true // Indicates request handling phase completed (proxying may have errors logged above)
}

// sendReply sends a SOCKS5 reply message to the client.
// BND.ADDR and BND.PORT are the address/port the server socket is bound to
// when connecting to the destination (use dstConn.LocalAddr()).
func sendReply(conn net.Conn, rep byte, bindAddr net.Addr) {
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+

	var reply []byte
	var atyp byte
	var hostBytes []byte
	var portBytes []byte = []byte{0, 0} // Default to port 0

	if bindAddr == nil {
		// Use IPv4 null address/port for general failures or when bind address is not applicable/available
		atyp = addrTypeIPv4
		hostBytes = net.IPv4zero.To4() // []byte{0, 0, 0, 0}
		// portBytes remains {0, 0}
	} else {
		// Parse the actual bound address provided
		tcpAddr, ok := bindAddr.(*net.TCPAddr)
		if !ok {
			log.Printf("Reply: Could not cast bind address %v to TCPAddr for %s", bindAddr, conn.RemoteAddr())
			// Fallback to IPv4 null address
			atyp = addrTypeIPv4
			hostBytes = net.IPv4zero.To4()
		} else {
			if ip4 := tcpAddr.IP.To4(); ip4 != nil {
				atyp = addrTypeIPv4
				hostBytes = ip4
			} else if ip6 := tcpAddr.IP.To16(); ip6 != nil {
				// Ensure it's not an IPv4-mapped IPv6 address if we prefer IPv4 representation
				// However, sticking to the actual IP type reported is usually correct.
				atyp = addrTypeIPv6
				hostBytes = ip6
			} else {
				log.Printf("Reply: Could not determine IP address type for bind address %s for %s", tcpAddr.IP.String(), conn.RemoteAddr())
				// Fallback to IPv4 null address
				atyp = addrTypeIPv4
				hostBytes = net.IPv4zero.To4()
			}
			// Get port
			binary.BigEndian.PutUint16(portBytes, uint16(tcpAddr.Port))
		}
	}

	// Construct the reply message
	reply = []byte{socks5Version, rep, 0x00, atyp}
	reply = append(reply, hostBytes...)
	reply = append(reply, portBytes...)

	_, err := conn.Write(reply)
	if err != nil {
		log.Printf("Reply: Error writing reply (REP: %d) to %s: %v", rep, conn.RemoteAddr(), err)
	} else {
		// log.Printf("Reply: Sent reply (REP: %d, ATYP: %d) to %s", rep, atyp, conn.RemoteAddr())
	}
}

func main() {
	// Define command line flags for username and password
	username := flag.String("user", "", "Username for SOCKS5 authentication")
	password := flag.String("pass", "", "Password for SOCKS5 authentication")
	listenAddr := flag.String("addr", "127.0.0.1:1080", "Address to listen on (host:port)")

	// Parse command line flags
	flag.Parse()

	// Configure authentication
	config := &Config{
		Username: *username,
		Password: *password,
	}

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("Failed to start SOCKS5 server on %s: %v", *listenAddr, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy server with User/Pass auth running on %s", listener.Addr())
	log.Printf("Use Username: '%s', Password: '%s'", config.Username, config.Password)

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Handle potential listener errors (e.g., file descriptor limits)
			log.Printf("Error accepting connection: %v", err)
			continue // Try accepting the next connection
		}
		// Handle each client connection in a new goroutine
		go handleConnection(conn, config)
	}
}
