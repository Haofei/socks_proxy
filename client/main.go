package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	// Needed for WaitGroup if used, though channels work well too
)

// --- Constants ---
const (
	socks5Version       = 0x05
	methodNoAuth        = 0x00
	methodUserPass      = 0x02
	noAcceptableMethods = 0xFF
	userAuthVersion     = 0x01 // Version for username/password auth subnegotiation

	cmdConnect     = 0x01
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIPv6   = 0x04

	authSuccess = 0x00
	// authFailure = 0x01 // Server uses 0x01

	replySuccess              = 0x00
	replyGeneralFailure       = 0x01
	replyCmdNotSupported      = 0x07
	replyAddrTypeNotSupported = 0x08
	// Add more reply codes as needed (e.g., network unreachable, host unreachable, connection refused)
)

// --- Configuration for the *REMOTE* Authenticated Proxy ---
type RemoteProxyConfig struct {
	Address  string // e.g., "remote.proxy.com:9999"
	Username string
	Password string
}

// --- Main Application ---
func main() {
	// --- Command Line Flags ---
	remoteProxyAddr := flag.String("remoteProxy", "", "Remote authenticated SOCKS5 proxy server address (host:port)")
	remoteUsername := flag.String("user", "", "Username for the remote SOCKS5 proxy")
	remotePassword := flag.String("pass", "", "Password for the remote SOCKS5 proxy")
	localListenAddr := flag.String("listen", "127.0.0.1:1080", "Local address to listen on for incoming SOCKS5 connections")

	flag.Parse()

	if *remoteProxyAddr == "" || *remoteUsername == "" || *remotePassword == "" {
		flag.Usage()
		log.Fatal("Error: Remote proxy address, username, and password are required.")
	}

	config := &RemoteProxyConfig{
		Address:  *remoteProxyAddr,
		Username: *remoteUsername,
		Password: *remotePassword,
	}

	// --- Start Local Listener ---
	listener, err := net.Listen("tcp", *localListenAddr)
	if err != nil {
		log.Fatalf("Failed to start local listener on %s: %v", *localListenAddr, err)
	}
	defer listener.Close()

	log.Printf("Local SOCKS5 proxy listening on %s", listener.Addr())
	log.Printf("Forwarding connections through remote proxy %s (User: %s)", config.Address, config.Username)

	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting local connection: %v", err)
			continue // Keep listening
		}
		// Handle each local client connection in a new goroutine
		go handleLocalConnection(localConn, config)
	}
}

// handleLocalConnection handles a connection from a local client (browser, app).
func handleLocalConnection(localConn net.Conn, remoteConfig *RemoteProxyConfig) {
	defer localConn.Close()
	log.Printf("Handling local connection from %s", localConn.RemoteAddr())

	reader := bufio.NewReader(localConn) // Use buffered reader for efficiency

	// --- 1. Local Client Greeting & Method Selection ---
	// We will accept the "No Authentication Required" method (0x00) from the local client.
	if err := handleLocalHandshake(reader, localConn); err != nil {
		log.Printf("Local handshake failed for %s: %v", localConn.RemoteAddr(), err)
		return
	}

	// --- 2. Local Client Request ---
	targetAddrString, err := handleLocalRequest(reader, localConn)
	if err != nil {
		log.Printf("Local request processing failed for %s: %v", localConn.RemoteAddr(), err)
		// Error reply should have been sent by handleLocalRequest
		return
	}

	if targetAddrString == "" {
		// Should not happen if handleLocalRequest succeeded without error, but check anyway
		log.Printf("Local request yielded empty target address for %s", localConn.RemoteAddr())
		return
	}

	log.Printf("Local client %s requests connection to %s", localConn.RemoteAddr(), targetAddrString)

	// --- 3. Connect to Target via Remote Authenticated Proxy ---
	log.Printf("Attempting to connect to %s via remote proxy %s for local client %s", targetAddrString, remoteConfig.Address, localConn.RemoteAddr())
	remoteConn, err := dialViaRemoteProxy(remoteConfig, targetAddrString)
	if err != nil {
		log.Printf("Failed to connect to target %s via remote proxy %s for %s: %v", targetAddrString, remoteConfig.Address, localConn.RemoteAddr(), err)
		// Map error to SOCKS reply code if possible, otherwise general failure
		// TODO: Enhance error mapping (e.g., net.DNSError -> host unreachable)
		sendLocalReply(localConn, replyGeneralFailure, nil) // Send failure reply to local client
		return
	}
	defer remoteConn.Close()

	log.Printf("Connection to %s via remote proxy established (local bind: %s)", targetAddrString, remoteConn.LocalAddr())

	// --- 4. Send Success Reply to Local Client ---
	// SOCKS5 requires a reply with the address/port the *server* (our proxy)
	// used to connect to the target. We get this from remoteConn.LocalAddr().
	// However, sending 0.0.0.0:0 often works fine for clients. For better compliance:
	bindAddr := remoteConn.LocalAddr()
	if err := sendLocalReply(localConn, replySuccess, bindAddr); err != nil {
		log.Printf("Failed to send success reply to local client %s: %v", localConn.RemoteAddr(), err)
		return // Can't proceed if reply fails
	}

	// --- 5. Relay Data ---
	log.Printf("Starting data relay between %s and %s (via %s)", localConn.RemoteAddr(), targetAddrString, remoteConfig.Address)
	errChan := make(chan error, 2)

	go func() {
		n, err := io.Copy(remoteConn, localConn)
		log.Printf("Relay: Copied %d bytes from local %s to remote %s", n, localConn.RemoteAddr(), targetAddrString)
		if err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("Relay Error (local->remote) for %s: %v", localConn.RemoteAddr(), err)
		}
		// Signal remote connection to close write side if local client closes read side
		if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		} else {
			remoteConn.Close() // Fallback for non-TCP
		}
		errChan <- err // Send error (or nil for EOF)
	}()

	go func() {
		n, err := io.Copy(localConn, remoteConn)
		log.Printf("Relay: Copied %d bytes from remote %s to local %s", n, targetAddrString, localConn.RemoteAddr())
		if err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("Relay Error (remote->local) for %s: %v", localConn.RemoteAddr(), err)
		}
		// Signal local connection to close write side if remote connection closes read side
		if tcpConn, ok := localConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		} else {
			localConn.Close() // Fallback for non-TCP
		}
		errChan <- err // Send error (or nil for EOF)
	}()

	// Wait for both copy operations to complete
	<-errChan
	<-errChan

	log.Printf("Data relay finished for local connection %s", localConn.RemoteAddr())
}

// handleLocalHandshake performs the SOCKS5 method negotiation with the local client.
// It accepts only the "No Authentication Required" method.
func handleLocalHandshake(reader *bufio.Reader, localConn net.Conn) error {
	// Read VER, NMETHODS
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return fmt.Errorf("reading handshake header: %w", err)
	}
	ver, nMethods := header[0], header[1]

	if ver != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", ver)
	}
	if nMethods == 0 {
		return errors.New("no methods specified")
	}

	// Read METHODS
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(reader, methods); err != nil {
		return fmt.Errorf("reading methods: %w", err)
	}

	// Check if NoAuth method is supported by the client
	supportsNoAuth := false
	for _, method := range methods {
		if method == methodNoAuth {
			supportsNoAuth = true
			break
		}
	}

	// Select NoAuth if supported, otherwise reject
	var response []byte
	if supportsNoAuth {
		response = []byte{socks5Version, methodNoAuth}
	} else {
		response = []byte{socks5Version, noAcceptableMethods}
	}

	if _, err := localConn.Write(response); err != nil {
		return fmt.Errorf("writing method selection response: %w", err)
	}

	if !supportsNoAuth {
		return errors.New("client does not support No Authentication method")
	}

	return nil // Handshake successful
}

// handleLocalRequest reads the SOCKS5 request from the local client and extracts the target address.
// It sends appropriate error replies back to the client if needed.
func handleLocalRequest(reader *bufio.Reader, localConn net.Conn) (targetAddrString string, err error) {
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	reqHeader := make([]byte, 4)
	if _, err = io.ReadFull(reader, reqHeader); err != nil {
		err = fmt.Errorf("reading request header: %w", err)
		// Don't send reply, connection likely broken
		return "", err
	}

	ver, cmd, atyp := reqHeader[0], reqHeader[1], reqHeader[3]

	if ver != socks5Version {
		err = fmt.Errorf("unsupported SOCKS version in request: %d", ver)
		sendLocalReply(localConn, replyGeneralFailure, nil) // Or a more specific error?
		return "", err
	}

	// We only support the CONNECT command
	if cmd != cmdConnect {
		err = fmt.Errorf("unsupported command: %d", cmd)
		sendLocalReply(localConn, replyCmdNotSupported, nil)
		return "", err
	}

	// Read DST.ADDR based on ATYP
	var targetHost string
	switch atyp {
	case addrTypeIPv4:
		ipBytes := make([]byte, net.IPv4len)
		if _, err = io.ReadFull(reader, ipBytes); err != nil {
			err = fmt.Errorf("reading IPv4 address: %w", err)
			return "", err
		}
		targetHost = net.IP(ipBytes).String()
	case addrTypeDomain:
		lenByte, errRead := reader.ReadByte()
		if errRead != nil {
			err = fmt.Errorf("reading domain length: %w", errRead)
			return "", err
		}
		domainBytes := make([]byte, lenByte)
		if _, err = io.ReadFull(reader, domainBytes); err != nil {
			err = fmt.Errorf("reading domain name: %w", err)
			return "", err
		}
		targetHost = string(domainBytes)
	case addrTypeIPv6:
		ipBytes := make([]byte, net.IPv6len)
		if _, err = io.ReadFull(reader, ipBytes); err != nil {
			err = fmt.Errorf("reading IPv6 address: %w", err)
			return "", err
		}
		targetHost = net.IP(ipBytes).String()
	default:
		err = fmt.Errorf("unsupported address type: %d", atyp)
		sendLocalReply(localConn, replyAddrTypeNotSupported, nil)
		return "", err
	}

	// Read DST.PORT
	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(reader, portBytes); err != nil {
		err = fmt.Errorf("reading port: %w", err)
		return "", err
	}
	targetPort := binary.BigEndian.Uint16(portBytes)

	targetAddrString = net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))
	return targetAddrString, nil // Success
}

// dialViaRemoteProxy connects to the target address through the specified remote SOCKS5 proxy.
// This function encapsulates the client logic from the previous example.
func dialViaRemoteProxy(config *RemoteProxyConfig, targetAddress string) (net.Conn, error) {
	// 1. Connect to the REMOTE SOCKS5 proxy server
	proxyConn, err := net.Dial("tcp", config.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to remote proxy server %s: %w", config.Address, err)
	}
	// Don't close proxyConn immediately, need to return it on success

	// 2. Client Greeting & Method Selection (Tell remote we support User/Pass)
	greeting := []byte{socks5Version, 1, methodUserPass}
	if _, err := proxyConn.Write(greeting); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("remote proxy: failed to send greeting: %w", err)
	}

	// 3. Server Method Selection Response (Expect remote to select User/Pass)
	methodResp := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, methodResp); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("remote proxy: failed to read method selection response: %w", err)
	}
	if methodResp[0] != socks5Version {
		proxyConn.Close()
		return nil, fmt.Errorf("remote proxy: unexpected SOCKS version %d", methodResp[0])
	}
	if methodResp[1] != methodUserPass {
		proxyConn.Close()
		return nil, fmt.Errorf("remote proxy: did not select User/Pass auth method (selected: %d)", methodResp[1])
	}

	// 4. Username/Password Authentication Subnegotiation
	usernameBytes := []byte(config.Username)
	passwordBytes := []byte(config.Password)
	ulen := len(usernameBytes)
	plen := len(passwordBytes)
	if ulen > 255 || plen > 255 || ulen == 0 || plen == 0 {
		proxyConn.Close()
		return nil, errors.New("remote proxy: invalid username/password length")
	}
	authReq := make([]byte, 0, 1+1+ulen+1+plen)
	authReq = append(authReq, userAuthVersion)
	authReq = append(authReq, byte(ulen))
	authReq = append(authReq, usernameBytes...)
	authReq = append(authReq, byte(plen))
	authReq = append(authReq, passwordBytes...)
	if _, err := proxyConn.Write(authReq); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("remote proxy: failed to send authentication request: %w", err)
	}

	// 5. Authentication Result
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, authResp); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("remote proxy: failed to read authentication response: %w", err)
	}
	if authResp[0] != userAuthVersion {
		proxyConn.Close()
		return nil, fmt.Errorf("remote proxy: unexpected auth subnegotiation version %d", authResp[0])
	}
	if authResp[1] != authSuccess {
		proxyConn.Close()
		return nil, fmt.Errorf("remote proxy: authentication failed (status: %d)", authResp[1])
	}

	// 6. Client Request (CONNECT to the *actual* target)
	targetHost, targetPortStr, err := net.SplitHostPort(targetAddress)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("invalid target address format %q: %w", targetAddress, err)
	}
	targetPort, err := strconv.ParseUint(targetPortStr, 10, 16)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("invalid target port %q: %w", targetPortStr, err)
	}

	var atyp byte
	var addrBytes []byte
	targetIP := net.ParseIP(targetHost)
	if targetIP != nil {
		if ipv4 := targetIP.To4(); ipv4 != nil {
			atyp = addrTypeIPv4
			addrBytes = ipv4
		} else {
			atyp = addrTypeIPv6
			addrBytes = targetIP.To16() // Assume IPv6 if not IPv4
		}
	} else { // Domain Name
		if len(targetHost) > 255 {
			proxyConn.Close()
			return nil, fmt.Errorf("target domain name too long: %s", targetHost)
		}
		atyp = addrTypeDomain
		addrBytes = []byte(targetHost)
		addrBytes = append([]byte{byte(len(addrBytes))}, addrBytes...) // Prepend length
	}

	req := make([]byte, 0, 4+len(addrBytes)+2)
	req = append(req, socks5Version, cmdConnect, 0x00, atyp)
	req = append(req, addrBytes...)
	portValueBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portValueBytes, uint16(targetPort))
	req = append(req, portValueBytes...)

	if _, err := proxyConn.Write(req); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("remote proxy: failed to send connection request for %s: %w", targetAddress, err)
	}

	// 7. Server Reply (from remote proxy)
	replyHeader := make([]byte, 4) // VER, REP, RSV, ATYP
	if _, err := io.ReadFull(proxyConn, replyHeader); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("remote proxy: failed to read reply header for %s: %w", targetAddress, err)
	}
	if replyHeader[0] != socks5Version {
		proxyConn.Close()
		return nil, fmt.Errorf("remote proxy: unexpected SOCKS version in reply %d", replyHeader[0])
	}
	if replyHeader[1] != replySuccess {
		proxyConn.Close()
		// TODO: Map remote proxy reply code to a more specific error?
		return nil, fmt.Errorf("remote proxy: connection failed for %s (reply code: %d)", targetAddress, replyHeader[1])
	}

	// Read and discard the BND.ADDR and BND.PORT from remote proxy reply
	bindAtyp := replyHeader[3]
	var bindAddrLen int
	switch bindAtyp {
	case addrTypeIPv4:
		bindAddrLen = net.IPv4len
	case addrTypeDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(proxyConn, lenByte); err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("remote proxy: failed to read bind domain length: %w", err)
		}
		bindAddrLen = int(lenByte[0])
	case addrTypeIPv6:
		bindAddrLen = net.IPv6len
	default:
		proxyConn.Close()
		return nil, fmt.Errorf("remote proxy: unsupported bind address type in reply: %d", bindAtyp)
	}
	if _, err := io.ReadFull(proxyConn, make([]byte, bindAddrLen+2)); err != nil { // +2 for port
		proxyConn.Close()
		return nil, fmt.Errorf("remote proxy: failed to read/discard bind address/port: %w", err)
	}

	// 8. Return the established connection (which goes through the remote proxy)
	return proxyConn, nil
}

// sendLocalReply sends a SOCKS5 reply message back to the connected local client.
// Uses 0.0.0.0:0 as bind address if bindAddr is nil or cannot be parsed.
func sendLocalReply(conn net.Conn, rep byte, bindAddr net.Addr) error {
	var atyp byte
	var hostBytes []byte
	var portBytes []byte = []byte{0, 0} // Default port 0

	if bindAddr == nil {
		atyp = addrTypeIPv4
		hostBytes = net.IPv4zero.To4() // 0.0.0.0
	} else {
		tcpAddr, ok := bindAddr.(*net.TCPAddr)
		if !ok {
			log.Printf("Reply: Could not cast bind address %v to TCPAddr for local client %s, using 0.0.0.0:0", bindAddr, conn.RemoteAddr())
			atyp = addrTypeIPv4
			hostBytes = net.IPv4zero.To4()
		} else {
			if ip4 := tcpAddr.IP.To4(); ip4 != nil {
				atyp = addrTypeIPv4
				hostBytes = ip4
			} else if ip6 := tcpAddr.IP.To16(); ip6 != nil {
				atyp = addrTypeIPv6
				hostBytes = ip6
			} else {
				log.Printf("Reply: Could not determine IP type for bind address %s for local client %s, using 0.0.0.0:0", tcpAddr.IP, conn.RemoteAddr())
				atyp = addrTypeIPv4
				hostBytes = net.IPv4zero.To4()
			}
			binary.BigEndian.PutUint16(portBytes, uint16(tcpAddr.Port))
		}
	}

	// Construct the reply message
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	reply := []byte{socks5Version, rep, 0x00, atyp}
	reply = append(reply, hostBytes...)
	reply = append(reply, portBytes...)

	_, err := conn.Write(reply)
	if err != nil {
		return fmt.Errorf("writing reply (REP: %d) to %s: %w", rep, conn.RemoteAddr(), err)
	}
	// log.Printf("Sent reply (REP: %d, ATYP: %d) to local client %s", rep, atyp, conn.RemoteAddr())
	return nil
}
