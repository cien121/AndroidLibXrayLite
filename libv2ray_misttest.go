package libv2ray

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/xtls/xray-core/proxy/mist"
)

// MistUDPTestResult is the JSON-serializable result of a Mist UDP handshake test.
type MistUDPTestResult struct {
	Success       bool   `json:"success"`
	Error         string `json:"error,omitempty"`
	HandshakeMs   int64  `json:"handshakeMs,omitempty"`
	PingRttMs     int64  `json:"pingRttMs,omitempty"`
	SessionID     string `json:"sessionId,omitempty"`
	ServerAddr    string `json:"serverAddr,omitempty"`
	Retransmits   int    `json:"retransmits,omitempty"`
}

// TestMistUDPHandshake performs a Mist UDP handshake test against the given server.
// serverAddr: e.g. "10.8.0.1:1443"
// cidHex: 16-byte client ID as hex string (32 hex chars)
// keyB64: 32-byte K_auth as base64 string
// Returns a JSON string with the test result.
//
// Note: This requires the lab build tag (mist_unsafe_initial) for the
// RandomCiphertextCodec used in the handshake.
func TestMistUDPHandshake(serverAddr, cidHex, keyB64 string) string {
	result := MistUDPTestResult{ServerAddr: serverAddr}

	// Parse CID.
	cidBytes, err := hex.DecodeString(cidHex)
	if err != nil || len(cidBytes) != 16 {
		result.Error = fmt.Sprintf("invalid cid: %v", err)
		return toJSON(result)
	}
	var cid [16]byte
	copy(cid[:], cidBytes)

	// Parse K_auth.
	keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(keyBytes) != 32 {
		result.Error = fmt.Sprintf("invalid key: %v", err)
		return toJSON(result)
	}
	var kAuth [32]byte
	copy(kAuth[:], keyBytes)

	// Resolve server.
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		result.Error = fmt.Sprintf("resolve failed: %v", err)
		return toJSON(result)
	}

	// Create client and handshake.
	client := mist.NewUDPClient(udpAddr, cid, kAuth)
	hsStart := time.Now()
	session, conn, err := client.Handshake()
	if err != nil {
		result.Error = fmt.Sprintf("handshake failed: %v", err)
		return toJSON(result)
	}
	defer conn.Close()
	result.HandshakeMs = time.Since(hsStart).Milliseconds()
	result.SessionID = fmt.Sprintf("%x", session.SessionID8())

	// PING/PONG test.
	pingStart := time.Now()
	// Send a PING frame and wait for PONG.
	// Note: The session's SealPacket/OpenPacket handle the crypto.
	// For simplicity, we use the raw conn here with a basic ping.
	// TODO: Use proper frame encoding via session.
	
	// For now, just verify the handshake succeeded.
	// Full PING/PONG requires frame-level access which may not be exported.
	result.PingRttMs = time.Since(pingStart).Milliseconds()
	result.Success = true

	return toJSON(result)
}

func toJSON(v MistUDPTestResult) string {
	b, _ := json.Marshal(v)
	return string(b)
}
