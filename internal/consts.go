package internal

const (
	ApiUrl     = "https://api.cloudflareclient.com"
	ApiVersion = "v0a4471"
	ConnectSNI   = "consumer-masque.cloudflareclient.com"
	L4ConnectSNI = "consumer-masque-proxy.cloudflareclient.com"
	// unused for now
	ZeroTierSNI   = "zt-masque.cloudflareclient.com"
	ConnectURI    = "https://cloudflareaccess.com"
	DefaultModel  = "PC"
	KeyTypeWg     = "curve25519"
	TunTypeWg     = "wireguard"
	KeyTypeMasque = "secp256r1"
	TunTypeMasque = "masque"
	DefaultLocale = "en_US"
)

// DefaultInitialPacketSize is the default QUIC packet size of the MASQUE connection, the
// size Cloudflare's own client uses. It fits a full 1280-byte tunnel packet in one DATAGRAM.
// Starting at quic-go's 1280 instead leaves full-size tunnel packets undeliverable until path
// MTU discovery grows the packet size, which stalls TLS handshakes through the tunnel.
const DefaultInitialPacketSize = 1350

// InitialPacketSizeHelp is the help text of the --initial-packet-size flag.
const InitialPacketSizeHelp = "QUIC packet size for the MASQUE connection; a nonzero value turns off path MTU discovery. 0 starts at 1280 with path MTU discovery, which drops full-size tunnel packets until discovery grows the size"

var Headers = map[string]string{
	"User-Agent":        "WARP for Android",
	"CF-Client-Version": "a-6.35-4471",
	"Content-Type":      "application/json; charset=UTF-8",
	"Connection":        "Keep-Alive",
}
