package blacklist

type dnsbl struct {
	Name    string
	Address string
	Hit     string
}

// Blacklists is a slice of the DNSBLs used. It is instantiated in the init().
var Blacklists []dnsbl

// init the Blacklists
func init() {
	Blacklists = []dnsbl{
		dnsbl{
			Name:    "Spam Cannibal",
			Address: "bl.spamcannibal.org",
			Hit:     "127.0.0.2",
		},
		dnsbl{
			Name:    "all.s5h.net",
			Address: "all.s5h.net",
			Hit:     "127.0.0.2",
		},
		dnsbl{
			Name:    "sbl.spamhaus.org",
			Address: "sbl.spamhaus.org",
			Hit:     "",
		},
	}
}
