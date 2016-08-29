package blacklist

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const checkMark = "\u2713"
const exMark = "\u2717"
const questionMark = "\u003F"

// CheckDomains checks if any domains are blacklisted
func CheckDomains(domains ...string) error {

	var wg sync.WaitGroup

	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			for _, blacklist := range Blacklists {

				err := blacklistLookup(d, blacklist)
				if err != nil {
					log.Printf("Lookup failed on: %s with: %v %v \n", blacklist.Name, err, exMark)
				}
			}
			wg.Done()
		}(domain)
	}
	wg.Wait()

	return nil
}

// CheckIPs checks if any ips are blacklisted
func CheckIPs(ips ...string) error {

	var wg sync.WaitGroup

	for _, ip := range ips {
		ipExplode := strings.Split(ip, ".")
		if len(ipExplode) != 4 {
			log.Printf("IP not properly formatted: %s %v \n", ip, exMark)
			continue
		}
		ipReverse := ipExplode[3] + "." + ipExplode[2] + "." + ipExplode[1] + "." + ipExplode[0]

		wg.Add(1)
		go func(ip string) {
			for _, blacklist := range Blacklists {
				err := blacklistLookup(ip, blacklist)
				if err != nil {
					log.Printf("Lookup failed on: %s with: %v %v \n", blacklist.Name, err, exMark)
				}
			}
			wg.Done()
		}(ipReverse)
	}
	wg.Wait()

	return nil
}

func blacklistLookup(target string, blacklist dnsbl) error {

	client := new(dns.Client)
	client.Timeout = 4 * time.Second

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(target+"."+blacklist.Address), dns.TypeA)

	resp, lookupTime, err := client.Exchange(msg, blacklist.Address+":53")
	if err != nil {
		return err
	}

	if len(resp.Answer) == 0 {
		log.Printf("Lookup for: %s on: %s yeilded no results and took: %v %v \n", target, blacklist.Name, lookupTime, checkMark)
		return nil
	}
	for _, ans := range resp.Answer {
		Arecord := ans.(*dns.A)
		if Arecord.A.String() == blacklist.Hit {
			log.Printf(`Lookup for: %s on: %s yeilded: %s and took: %v
				%s is blacklisted on %s %v
				Request removal at (%s)`, target, blacklist.Name, Arecord.A, lookupTime, target, blacklist.Name, exMark, blacklist.RemovalAddress)
		} else {
			log.Printf("Lookup for: %s on: %s yeilded: %s and took: %v %v \n", target, blacklist.Name, Arecord.A, lookupTime, questionMark)
		}
	}

	return nil
}
