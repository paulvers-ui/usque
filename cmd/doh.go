package cmd

import (
	"github.com/Diniboy1123/usque/internal/doh"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// addDoHFlags registers the DNS-over-HTTPS flags shared by the proxy modes.
func addDoHFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("doh", true, "Resolve proxy target names with DNS-over-HTTPS (--doh-url) instead of plain UDP/53 to -d")
	cmd.Flags().StringArray("doh-url", doh.DefaultEndpoints, "DNS-over-HTTPS endpoints, tried in order; IP-literal hosts need no bootstrap lookup")
	cmd.Flags().String("dnssec", "validate", "DNSSEC enforcement for DoH answers: validate (reject bogus answers, and unauthenticated ones for names known to be signed), strict (require every answer to be authenticated) or off")
}

// newDoHClient returns the DoH client for a proxy command, or nil with --doh=false.
// With a tunnel stack its queries travel through the MASQUE tunnel; with nil, over
// the host network.
func newDoHClient(cmd *cobra.Command, tunNet *netstack.Net) (*doh.Client, error) {
	enabled, err := cmd.Flags().GetBool("doh")
	if err != nil || !enabled {
		return nil, err
	}
	endpoints, err := cmd.Flags().GetStringArray("doh-url")
	if err != nil {
		return nil, err
	}
	modeFlag, err := cmd.Flags().GetString("dnssec")
	if err != nil {
		return nil, err
	}
	mode, err := doh.ParseMode(modeFlag)
	if err != nil {
		return nil, err
	}
	opts := doh.Options{Endpoints: endpoints, Mode: mode}
	if tunNet != nil {
		opts.Dial = tunNet.DialContext
	}
	return doh.New(opts)
}
