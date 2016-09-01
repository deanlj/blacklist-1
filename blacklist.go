package blacklist

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const checkMark = "\u2713"
const exMark = "\u2717"
const questionMark = "\u003F"

// Check checks if any domains or IP addresses are blacklisted
func Check(addresses ...string) error {

	var wg sync.WaitGroup
	var queries []*dnsblQuery

	for _, address := range addresses {

		query := dnsblQuery{
			Value:  address,
			Target: address,
		}

		queries = append(queries, &query)

		if net.ParseIP(address) != nil {
			ipExplode := strings.Split(address, ".")
			if len(ipExplode) != 4 {
				log.Printf("IP must be IPv4: %s %v \n", address, exMark)
				continue
			}
			query.Target = ipExplode[3] + "." + ipExplode[2] + "." + ipExplode[1] + "." + ipExplode[0]
		}

		wg.Add(1)
		go func(q *dnsblQuery) {
			for _, blacklist := range Blacklists {
				wg.Add(1)
				go func(bl dnsbl) {
					result, err := blacklistLookup(*q, bl)
					if err != nil {
						log.Printf("%s: Lookup failed on: %s with: %v %v \n", q.Value, bl.Name, err, exMark)
					} else {
						log.Println(q.Value + ": " + result)
					}
					wg.Done()
				}(blacklist)
			}
			wg.Done()
		}(&query)
	}
	wg.Wait()

	return nil
}

// CheckDomains checks if any domains are blacklisted
// This is probably depracated now
func CheckDomains(domains ...string) error {

	var wg sync.WaitGroup

	for _, domain := range domains {

		query := dnsblQuery{
			Value:  domain,
			Target: domain,
		}

		wg.Add(1)
		go func(q *dnsblQuery) {
			for _, blacklist := range Blacklists {

				result, err := blacklistLookup(*q, blacklist)
				if err != nil {
					q.Results = append(q.Results, fmt.Sprintf("Lookup failed on: %s with: %v %v \n", blacklist.Name, err, exMark))
				} else {
					q.Results = append(q.Results, result)
				}
			}
			wg.Done()
		}(&query)
	}
	wg.Wait()

	return nil
}

// CheckIPs checks if any ips are blacklisted
// This is probably depracated now
func CheckIPs(ips ...string) error {

	var wg sync.WaitGroup

	for _, ip := range ips {

		query := dnsblQuery{
			Value: ip,
		}

		ipExplode := strings.Split(ip, ".")
		if len(ipExplode) != 4 {
			log.Printf("IP must be IPv4: %s %v \n", ip, exMark)
			continue
		}
		query.Target = ipExplode[3] + "." + ipExplode[2] + "." + ipExplode[1] + "." + ipExplode[0]

		wg.Add(1)
		go func(q *dnsblQuery) {
			for _, blacklist := range Blacklists {
				result, err := blacklistLookup(*q, blacklist)
				if err != nil {
					q.Results = append(q.Results, fmt.Sprintf("Lookup failed on: %s with: %v %v \n", blacklist.Name, err, exMark))
				} else {
					q.Results = append(q.Results, result)
				}
			}
			wg.Done()
		}(&query)
	}
	wg.Wait()

	return nil
}

func blacklistLookup(query dnsblQuery, blacklist dnsbl) (string, error) {

	client := new(dns.Client)
	client.Timeout = 4 * time.Second

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(query.Target+"."+blacklist.Address), dns.TypeA)

	resp, lookupTime, err := client.Exchange(msg, blacklist.Address+":53")
	if err != nil {
		return "", err
	}

	// No Answer means the domain is not blacklisted
	if len(resp.Answer) == 0 {
		return fmt.Sprintf("Lookup on: %s yeilded no results and took: %v %v", blacklist.Name, lookupTime, checkMark), nil
	}

	// TODO: This loops over multiple answers, function will return on the first though
	// Probably just need to check if there was an answer and not the specific value (yet)
	for _, ans := range resp.Answer {
		Arecord := ans.(*dns.A)
		if Arecord.A.String() == blacklist.Hit {
			return fmt.Sprintf(`Lookup on: %s yeilded: %s and took: %v
				%s is blacklisted on %s %v
				Request removal at (%s)`, blacklist.Name, Arecord.A, lookupTime, query.Value, blacklist.Name, exMark, blacklist.RemovalAddress), nil
		}

		return fmt.Sprintf("Lookup on: %s yeilded: %s and took: %v %v", blacklist.Name, Arecord.A, lookupTime, questionMark), nil
	}

	return "", nil
}
