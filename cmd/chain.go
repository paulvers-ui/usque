package cmd

import (
	"context"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/internal/chain"
	"github.com/Diniboy1123/usque/internal/doh"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/device"
)

// WARP2's tunnel carries IPv6 (needs a 1280-byte link) and never exceeds an
// Ethernet-sized packet.
const (
	minExitMTU   = 1280
	maxTunnelMTU = 1500
)

var chainCmd = &cobra.Command{
	Use:   "chain",
	Short: "SOCKS5 proxy over WARP1 -> WireGuard -> WARP2, nested in one process",
	Long: "Runs three nested tunnels: WARP1 (-c) over the host network hides you from the ISP, " +
		"a WireGuard hop (--wg) inside WARP1 gives a new location, and WARP2 (--exit-config) " +
		"inside the WireGuard hop gives a Cloudflare egress IP. The SOCKS5 proxy egresses via WARP2.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}
		f := cmd.Flags()
		str := func(n string) string { v, _ := f.GetString(n); return v }
		boolean := func(n string) bool { v, _ := f.GetBool(n); return v }
		integer := func(n string) int { v, _ := f.GetInt(n); return v }
		dur := func(n string) time.Duration { v, _ := f.GetDuration(n); return v }

		wgPath, exitPath := str("wg"), str("exit-config")
		if wgPath == "" || exitPath == "" {
			log.Fatal("chain: --wg and --exit-config are required")
		}
		wgFile, err := os.Open(wgPath)
		if err != nil {
			log.Fatalf("chain: %v", err)
		}
		wgCfg, err := chain.ParseWGConfig(wgFile)
		_ = wgFile.Close()
		if err != nil {
			log.Fatalf("chain: %s: %v", wgPath, err)
		}
		exitCfg, err := config.LoadConfigFile(exitPath)
		if err != nil {
			log.Fatalf("chain: %v", err)
		}
		if exitCfg.PrivateKey == config.AppConfig.PrivateKey {
			log.Println("chain: WARNING: WARP1 and WARP2 use the same identity; register a second one for --exit-config")
		}

		ctx := context.Background()
		ips, _ := f.GetUint16("initial-packet-size")
		insecure := boolean("insecure")
		mtu1 := integer("mtu")

		// Hop 1: WARP1 over the host network.
		warp1, err := chain.StartWarp(ctx, chain.WarpHop{
			Name: "warp1", Config: &config.AppConfig, SNI: str("sni-address"),
			UseHTTP2: boolean("http2"), UseIPv6: boolean("ipv6"), ConnectPort: integer("connect-port"),
			InitialPacketSize: ips, MTU: mtu1, Keepalive: dur("keepalive-period"),
			ReconnectDelay: dur("reconnect-delay"), AlwaysReconnect: true, Insecure: insecure,
			FallbackHTTP2After: integer("http2-fallback-after"),
		}, nil)
		if err != nil {
			log.Fatalf("chain: %v", err)
		}

		// Name lookups for the wg0 endpoint go through WARP1.
		resolver, err := doh.New(doh.Options{Endpoints: doh.DefaultEndpoints, Mode: doh.ModeValidate, Dial: warp1.DialContext})
		if err != nil {
			log.Fatalf("chain: %v", err)
		}

		// Hop 2: wg0 inside WARP1.
		logLevel := device.LogLevelError
		if boolean("wg-verbose") {
			logLevel = device.LogLevelVerbose
		}
		wg0, wgMTU, err := chain.StartWG(ctx, chain.WGHop{
			Config: wgCfg, UnderMTU: mtu1, Keepalive: integer("wg-keepalive"), MTU: integer("wg-mtu"),
			Resolver: resolver, LogLevel: logLevel,
		}, warp1)
		if err != nil {
			log.Fatalf("chain: %v", err)
		}

		// Hop 3: WARP2 inside wg0.
		exitHTTP2 := true
		switch str("exit-transport") {
		case "h2":
		case "h3":
			exitHTTP2 = false
			log.Printf("chain: WARNING: exit over QUIC needs ~1480-byte packets through wg0 (have %d); expect stalls", wgMTU)
		case "auto":
			exitHTTP2 = !chain.ExitTransportFits(wgMTU)
		default:
			log.Fatal("chain: --exit-transport must be auto, h2 or h3")
		}
		exitIPS := uint16(0)
		if !exitHTTP2 {
			exitIPS = uint16(wgMTU - 28)
		}
		exitMTU := integer("exit-mtu")
		if exitMTU < minExitMTU || exitMTU > maxTunnelMTU {
			log.Fatalf("chain: --exit-mtu must be %d..%d (IPv6 needs at least %d)", minExitMTU, maxTunnelMTU, minExitMTU)
		}
		warp2, err := chain.StartWarp(ctx, chain.WarpHop{
			Name: "warp2", Config: exitCfg, SNI: str("exit-sni"),
			UseHTTP2: exitHTTP2, ConnectPort: integer("exit-connect-port"), InitialPacketSize: exitIPS, MTU: exitMTU,
			Keepalive: dur("keepalive-period"), ReconnectDelay: dur("reconnect-delay"),
			AlwaysReconnect: true, Insecure: insecure,
		}, wg0)
		if err != nil {
			log.Fatalf("chain: %v", err)
		}

		// SOCKS5 + DoH egress through WARP2.
		dohClient, err := newDoHClient(cmd, warp2)
		if err != nil {
			log.Fatalf("chain: DoH: %v", err)
		}
		var dnsAddrs []netip.Addr
		for _, d := range []string{"1.1.1.1", "1.0.0.1"} {
			dnsAddrs = append(dnsAddrs, netip.MustParseAddr(d))
		}
		server, err := internal.NewSOCKS5Server(internal.SOCKS5Config{
			Addr:       net.JoinHostPort(str("bind"), str("port")),
			Username:   str("username"),
			Password:   str("password"),
			Resolver:   &internal.TunnelDNSResolver{DNSAddrs: dnsAddrs, Timeout: 5 * time.Second, DoH: dohClient, TunNet: warp2},
			TunNet:     warp2,
			UDPTimeout: dur("udp-timeout"),
			Logger:     log.New(internal.NewTZStampWriter(os.Stderr), "socks5: ", 0),
		})
		if err != nil {
			log.Fatalf("chain: SOCKS: %v", err)
		}
		log.Printf("chain: SOCKS proxy listening on %s:%s (apps -> warp2 -> wg0 -> warp1 -> ISP)", str("bind"), str("port"))
		if err := server.Start(); err != nil {
			log.Fatalf("chain: SOCKS: %v", err)
		}
	},
}

func init() {
	f := chainCmd.Flags()
	f.StringP("bind", "b", "127.0.0.1", "Address to bind the SOCKS proxy to")
	f.StringP("port", "p", "1080", "Port to listen on for SOCKS proxy")
	f.StringP("username", "u", "", "SOCKS username")
	f.StringP("password", "w", "", "SOCKS password")
	f.String("wg", "", "wg-quick config of the middle WireGuard hop (plain WireGuard)")
	f.String("exit-config", "", "usque config.json of the second WARP identity (exit hop)")
	f.String("exit-transport", "auto", "Exit hop transport: auto, h2 or h3. auto picks HTTP/2 because QUIC does not fit through wg0 inside WARP1")
	f.String("exit-sni", internal.ConnectSNI, "SNI for the exit hop (hidden inside wg0, the ISP never sees it)")
	f.Int("wg-keepalive", 25, "PersistentKeepalive for wg0 when its config sets none; keeps Cloudflare's NAT open")
	f.Bool("wg-verbose", false, "Verbose WireGuard logs")
	f.Int("wg-mtu", 0, "wg0 inner MTU; 0 = the config's MTU. Always capped to what fits inside WARP1 (-m minus 60, or 80 for an IPv6 endpoint)")
	f.Int("exit-mtu", 1280, "WARP2 (exit) tunnel MTU")
	f.Int("exit-connect-port", 443, "Port for the WARP2 MASQUE connection (inside wg0)")
	f.Int("http2-fallback-after", 2, "WARP1: switch from QUIC to HTTP/2 after this many failed connects in a row, for networks that block UDP 443 (0 = never)")
	f.StringP("sni-address", "s", internal.ConnectSNI, "SNI for WARP1 (the only hop the ISP sees)")
	f.IntP("connect-port", "P", 443, "Port for the WARP1 MASQUE connection")
	f.BoolP("ipv6", "6", false, "Use IPv6 for the WARP1 MASQUE connection")
	f.Bool("http2", false, "WARP1 over HTTP/2 instead of QUIC")
	f.IntP("mtu", "m", 1280, "WARP1 tunnel MTU; wg0's MTU is derived from it")
	f.Uint16P("initial-packet-size", "i", internal.DefaultInitialPacketSize, internal.InitialPacketSizeHelp)
	f.DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connections")
	f.DurationP("reconnect-delay", "r", 1*time.Second, "Delay between reconnect attempts")
	f.Duration("udp-timeout", 60*time.Second, "Idle deadline for SOCKS5 UDP relays")
	f.Bool("insecure", false, "Disable endpoint certificate pinning (testing only)")
	addDoHFlags(chainCmd)
	rootCmd.AddCommand(chainCmd)
}
