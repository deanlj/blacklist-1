package blacklist

import (
	"testing"
)

// TestCheckDomains tests blacklist.CheckDomains()
func TestCheckDomains(t *testing.T) {
	t.Log("Testing Domain Check")
	CheckDomains("uk2-mail.net", "pressly.com", "gmail.com")
}

// TestCheckDomains tests blacklist.CheckIPs()
func TestCheckIPs(t *testing.T) {
	t.Log("Testing IP check")
	CheckIPs("127.0.0.2", "127.0.0.1.2", "127.0.0", "127.0.0.1", "127.0.0.2")
}
