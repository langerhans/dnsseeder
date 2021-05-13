package main

import (
	"github.com/btcsuite/btcd/wire"
	"log"
	//	"sync"

	"github.com/miekg/dns"
)

const flagsX1 = wire.SFNodeNetwork
const flagsX5 = wire.SFNodeNetwork|wire.SFNodeBloom
const flagsX9 = wire.SFNodeNetwork|wire.SFNodeWitness
const flagsXd = wire.SFNodeNetwork|wire.SFNodeBloom|wire.SFNodeWitness

// updateDNS updates the current slices of dns.RR so incoming requests get a
// fast answer
func updateDNS(s *dnsseeder) {
	var rr4std, rr4stdx1, rr4stdx5, rr4stdx9, rr4stdxd, rr4non []dns.RR
	var rr6std, rr6stdx1, rr6stdx5, rr6stdx9, rr6stdxd, rr6non []dns.RR

	s.mtx.RLock()

	for _, nd := range s.theList {
		if nd.status != statusCG {
			continue
		}

		switch nd.dnsType {
		case dnsV4Std:
			addDnsV4Std(s, nd, &rr4std, &rr4stdx1, &rr4stdx5, &rr4stdx9, &rr4stdxd)
		case dnsV4Non:
			addDnsV4Non(s, nd, &rr4non)
		case dnsV6Std:
			addDnsV6Std(s, nd, &rr6std, &rr6stdx1, &rr6stdx5, &rr6stdx9, &rr6stdxd)
		case dnsV6Non:
			addDnsV6Non(s, nd, &rr6non)
		}
	}

	s.mtx.RUnlock()

	config.dnsmtx.Lock()

	// update the map holding the details for this seeder
	config.dns[s.dnsHost+".A"] = rr4std
	config.dns["x1."+s.dnsHost+".A"] = rr4stdx1
	config.dns["x5."+s.dnsHost+".A"] = rr4stdx5
	config.dns["x9."+s.dnsHost+".A"] = rr4stdx9
	config.dns["xd."+s.dnsHost+".A"] = rr4stdxd
	config.dns["nonstd."+s.dnsHost+".A"] = rr4non

	config.dns[s.dnsHost+".AAAA"] = rr6std
	config.dns["x1."+s.dnsHost+".AAAA"] = rr6stdx1
	config.dns["x5."+s.dnsHost+".AAAA"] = rr6stdx5
	config.dns["x9."+s.dnsHost+".AAAA"] = rr6stdx9
	config.dns["xd."+s.dnsHost+".AAAA"] = rr6stdxd
	config.dns["nonstd."+s.dnsHost+".AAAA"] = rr6non

	config.dnsmtx.Unlock()
	
	if config.stats {
		s.counts.mtx.RLock()
		log.Printf("%s - DNS available: v4std: %v v4non: %v v6std: %v v6non: %v\n", s.name, len(rr4std), len(rr4non), len(rr6std), len(rr6non))
		log.Printf("%s - DNS counts: v4std: %v v4non: %v v6std: %v v6non: %v total: %v\n",
			s.name,
			s.counts.DNSCounts[dnsV4Std],
			s.counts.DNSCounts[dnsV4Non],
			s.counts.DNSCounts[dnsV6Std],
			s.counts.DNSCounts[dnsV6Non],
			s.counts.DNSCounts[dnsV4Std]+s.counts.DNSCounts[dnsV4Non]+s.counts.DNSCounts[dnsV6Std]+s.counts.DNSCounts[dnsV6Non])

		s.counts.mtx.RUnlock()

	}
}

func addDnsV6Std(s *dnsseeder, nd *node, rr6std *[]dns.RR, rr6stdx1 *[]dns.RR, rr6stdx5 *[]dns.RR, rr6stdx9 *[]dns.RR, rr6stdxd *[]dns.RR) {
	r := new(dns.AAAA)
	r.Hdr = dns.RR_Header{Name: s.dnsHost + ".", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.ttl}
	r.AAAA = nd.na.IP
	
	if len(*rr6std) < 25 {
		*rr6std = append(*rr6std, r)
	}
	if nd.services&flagsX1 == flagsX1 && len(*rr6stdx1) < 25 {
		*rr6stdx1 = append(*rr6stdx1, r)
	}
	if nd.services&flagsX5 == flagsX5 && len(*rr6stdx5) < 25 {
		*rr6stdx5 = append(*rr6stdx5, r)
	}
	if nd.services&flagsX9 == flagsX9 && len(*rr6stdx9) < 25 {
		*rr6stdx9 = append(*rr6stdx9, r)
	}
	if nd.services&flagsXd == flagsXd && len(*rr6stdxd) < 25{
		*rr6stdxd = append(*rr6stdxd, r)
	}
}

func addDnsV6Non(s *dnsseeder, nd *node, rr6non *[]dns.RR) {
	if len(*rr6non) < 50 {
		r := new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: "nonstd." + s.dnsHost + ".", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.ttl}
		r.AAAA = nd.na.IP
		*rr6non = append(*rr6non, r)
		r = new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: "nonstd." + s.dnsHost + ".", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.ttl}
		r.AAAA = nd.nonstdIP
		*rr6non = append(*rr6non, r)
	}
}

func addDnsV4Std(s *dnsseeder, nd *node, rr4std *[]dns.RR, rr4stdx1 *[]dns.RR, rr4stdx5 *[]dns.RR, rr4stdx9 *[]dns.RR, rr4stdxd *[]dns.RR) {
	r := new(dns.A)
	r.Hdr = dns.RR_Header{Name: s.dnsHost + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.ttl}
	r.A = nd.na.IP

	if len(*rr4std) < 25 {
		*rr4std = append(*rr4std, r)
	}
	if nd.services&flagsX1 == flagsX1 && len(*rr4stdx1) < 25 {
		*rr4stdx1 = append(*rr4stdx1, r)
	}
	if nd.services&flagsX5 == flagsX5 && len(*rr4stdx5) < 25 {
		*rr4stdx5 = append(*rr4stdx5, r)
	}
	if nd.services&flagsX9 == flagsX9 && len(*rr4stdx9) < 25 {
		*rr4stdx9 = append(*rr4stdx9, r)
	}
	if nd.services&flagsXd == flagsXd && len(*rr4stdxd) < 25{
		*rr4stdxd = append(*rr4stdxd, r)
	}
}

func addDnsV4Non(s *dnsseeder, nd *node, rr4non *[]dns.RR) {
	if len(*rr4non) < 50 {
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: "nonstd." + s.dnsHost + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.ttl}
		r.A = nd.na.IP
		*rr4non = append(*rr4non, r)
		r = new(dns.A)
		r.Hdr = dns.RR_Header{Name: "nonstd." + s.dnsHost + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.ttl}
		r.A = nd.nonstdIP
		*rr4non = append(*rr4non, r)
	}
}

// handleDNS processes a DNS request from remote client and returns
// a list of current ip addresses that the crawlers consider current.
func handleDNS(w dns.ResponseWriter, r *dns.Msg) {

	m := &dns.Msg{MsgHdr: dns.MsgHdr{
		Authoritative:      true,
		RecursionAvailable: false,
	}}
	m.SetReply(r)

	var qtype string

	switch r.Question[0].Qtype {
	case dns.TypeA:
		qtype = "A"
	case dns.TypeAAAA:
		qtype = "AAAA"
	case dns.TypeTXT:
		qtype = "TXT"
	case dns.TypeMX:
		qtype = "MX"
	case dns.TypeNS:
		qtype = "NS"
	default:
		qtype = "UNKNOWN"
	}

	config.dnsmtx.RLock()
	// if the dns map does not have a key for the request it will return an empty slice
	m.Answer = config.dns[r.Question[0].Name+qtype]
	config.dnsmtx.RUnlock()

	w.WriteMsg(m)

	if config.debug {
		log.Printf("debug - DNS response Type: standard  To IP: %s  Query Type: %s\n", w.RemoteAddr().String(), qtype)
	}
	// update the stats in a goroutine
	go updateDNSCounts(r.Question[0].Name, qtype)
}

// serve starts the requested DNS server listening on the requested port
func serve(net, port string) {
	server := &dns.Server{Addr: ":" + port, Net: net, TsigSecret: nil}
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Failed to setup the "+net+" server: %v\n", err)
	}
}

/*

 */
