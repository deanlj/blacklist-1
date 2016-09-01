package blacklist

type dnsbl struct {
	Name           string
	Address        string
	Hit            string
	RemovalAddress string
}

type dnsblQuery struct {
	Value   string
	Target  string
	Results []string
}

// Blacklists is a slice of the DNSBLs used. It is instantiated in the init().
var Blacklists []dnsbl

// init the Blacklists
func init() {
	Blacklists = []dnsbl{
		dnsbl{ // dial udp i/o timeout
			Name:           "Spam Cannibal",
			Address:        "bl.spamcannibal.org",
			Hit:            "127.0.0.2",
			RemovalAddress: "http://www.spamcannibal.org/cannibal.cgi",
		},
		dnsbl{
			Name:           "all.s5h.net",
			Address:        "all.s5h.net",
			Hit:            "127.0.0.2",
			RemovalAddress: "http://www.usenix.org.uk/content/rblremove",
		},
		dnsbl{ // no such host
			Name:           "SPAMHAUS",
			Address:        "zen.spamhaus.org",
			Hit:            "127.0.0.2",
			RemovalAddress: "https://www.spamhaus.org/lookup/",
		},
		dnsbl{ // no such host
			Name:           "Barracuda Central",
			Address:        "b.barracudacentral.org",
			Hit:            "127.0.0.2",
			RemovalAddress: "http://barracudacentral.org/rbl/removal-request",
		},
		dnsbl{ // read udp i/o timeout
			Name:           "Passive Spam Block List",
			Address:        "psbl.surriel.com",
			Hit:            "127.0.0.2",
			RemovalAddress: "https://psbl.org/remove",
		},
		dnsbl{ // connection refused
			Name:           "SORBS",
			Address:        "dnsbl.sorbs.net",
			Hit:            "127.0.0.2",
			RemovalAddress: "http://www.sorbs.net/delisting/overview.shtml",
		},
	}
}
