package chain

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// WGPeer is one [Peer] section of a wg-quick config.
type WGPeer struct {
	PublicKey           [32]byte
	PresharedKey        *[32]byte
	AllowedIPs          []netip.Prefix
	Endpoint            string // host:port as written; resolved later
	PersistentKeepalive int    // seconds, 0 = unset
}

// WGConfig is a parsed wg-quick style config (plain WireGuard only).
type WGConfig struct {
	PrivateKey [32]byte
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int // 0 = unset
	Peers      []WGPeer
}

// amneziaKeys are AmneziaWG obfuscation settings vanilla wireguard-go cannot speak.
var amneziaKeys = map[string]bool{"jc": true, "jmin": true, "jmax": true, "s1": true, "s2": true,
	"s3": true, "s4": true, "h1": true, "h2": true, "h3": true, "h4": true, "i1": true, "i2": true,
	"i3": true, "i4": true, "i5": true}

func parseKey(v string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil || len(b) != 32 {
		return k, fmt.Errorf("invalid WireGuard key")
	}
	copy(k[:], b)
	return k, nil
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ParseWGConfig parses a wg-quick config. Keys inside the file are never logged.
func ParseWGConfig(r io.Reader) (*WGConfig, error) {
	cfg := &WGConfig{}
	var peer *WGPeer
	section := ""
	haveKey := false
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				cfg.Peers = append(cfg.Peers, WGPeer{})
				peer = &cfg.Peers[len(cfg.Peers)-1]
			} else if section != "interface" {
				return nil, fmt.Errorf("line %d: unknown section [%s]", lineNo, section)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", lineNo)
		}
		key := strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if amneziaKeys[key] {
			return nil, fmt.Errorf("line %d: %s is an AmneziaWG setting; only plain WireGuard is supported", lineNo, strings.TrimSpace(k))
		}
		var err error
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				cfg.PrivateKey, err = parseKey(v)
				haveKey = err == nil
			case "address":
				for _, a := range splitList(v) {
					p, perr := parsePrefix(a)
					if perr != nil {
						return nil, fmt.Errorf("line %d: bad Address %q", lineNo, a)
					}
					cfg.Addresses = append(cfg.Addresses, p)
				}
			case "dns":
				for _, d := range splitList(v) {
					if a, derr := netip.ParseAddr(d); derr == nil {
						cfg.DNS = append(cfg.DNS, a)
					} // search domains are ignored
				}
			case "mtu":
				cfg.MTU, err = strconv.Atoi(v)
			case "listenport", "table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark":
				// irrelevant for a userspace hop
			default:
				return nil, fmt.Errorf("line %d: unsupported [Interface] key %s", lineNo, strings.TrimSpace(k))
			}
		case "peer":
			switch key {
			case "publickey":
				peer.PublicKey, err = parseKey(v)
			case "presharedkey":
				var psk [32]byte
				psk, err = parseKey(v)
				peer.PresharedKey = &psk
			case "allowedips":
				for _, a := range splitList(v) {
					p, perr := parsePrefix(a)
					if perr != nil {
						return nil, fmt.Errorf("line %d: bad AllowedIPs %q", lineNo, a)
					}
					peer.AllowedIPs = append(peer.AllowedIPs, p)
				}
			case "endpoint":
				peer.Endpoint = v
			case "persistentkeepalive":
				if v == "off" {
					peer.PersistentKeepalive = 0
				} else {
					peer.PersistentKeepalive, err = strconv.Atoi(v)
				}
			default:
				return nil, fmt.Errorf("line %d: unsupported [Peer] key %s", lineNo, strings.TrimSpace(k))
			}
		default:
			return nil, fmt.Errorf("line %d: key outside of a section", lineNo)
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %s: %v", lineNo, strings.TrimSpace(k), err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !haveKey {
		return nil, fmt.Errorf("missing [Interface] PrivateKey")
	}
	if len(cfg.Addresses) == 0 {
		return nil, fmt.Errorf("missing [Interface] Address")
	}
	if len(cfg.Peers) != 1 {
		return nil, fmt.Errorf("exactly one [Peer] is supported, found %d", len(cfg.Peers))
	}
	if cfg.Peers[0].Endpoint == "" {
		return nil, fmt.Errorf("[Peer] Endpoint is required")
	}
	return cfg, nil
}

// SplitEndpoint returns host and port of the peer endpoint.
func SplitEndpoint(ep string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return "", 0, fmt.Errorf("bad Endpoint %q: %v", ep, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return "", 0, fmt.Errorf("bad Endpoint port %q", port)
	}
	return host, uint16(p), nil
}

// UAPI renders the config for wireguard-go's IpcSet with the peer endpoint
// already resolved to ep.
func (c *WGConfig) UAPI(ep netip.AddrPort, keepalive int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(c.PrivateKey[:]))
	fmt.Fprintf(&b, "replace_peers=true\n")
	p := c.Peers[0]
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
	if p.PresharedKey != nil {
		fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(p.PresharedKey[:]))
	}
	fmt.Fprintf(&b, "endpoint=%s\n", ep.String())
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	fmt.Fprintf(&b, "replace_allowed_ips=true\n")
	for _, a := range p.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", a.String())
	}
	return b.String()
}
