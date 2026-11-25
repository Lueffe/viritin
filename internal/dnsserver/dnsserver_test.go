package dnsserver

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func serve(t *testing.T, h mdns.Handler) (addr string, stop func()) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: h}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

func ask(t *testing.T, addr, name string, qt uint16) *mdns.Msg {
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(name), qt)
	c := &mdns.Client{Timeout: 2 * time.Second}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

func TestInterceptMatching(t *testing.T) {
	cases := []struct {
		q, p string
		want bool
	}{
		{"radio.vtuner.com", "*.vtuner.com", true}, {"vtuner.com", "*.vtuner.com", true}, {"VTUNER.COM", "*.vtuner.com", true},
		{"notvtuner.com", "*.vtuner.com", false}, {"example.org", "*.vtuner.com", false},
		{"Exact.Example", "exact.example", true}, {"a.exact.example", "exact.example", false},
	}
	for _, c := range cases {
		if got := Matches(c.q, c.p); got != c.want {
			t.Errorf("Matches(%q,%q)=%v", c.q, c.p, got)
		}
	}
}

// upstream stands in for 8.8.8.8: it answers every A query with 9.9.9.9.
func upstream(t *testing.T) (port string, stop func()) {
	addr, stop := serve(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		m.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: r.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP("9.9.9.9")}}
		_ = w.WriteMsg(m)
	}))
	_, p, _ := net.SplitHostPort(addr)
	return p, stop
}

func TestForwardsNonInterceptedNames(t *testing.T) {
	up, stopUp := upstream(t)
	defer stopUp()
	s := New("*.vtuner.com", "127.0.0.1", "10.1.2.3", false, "")
	s.UpstreamPort = up
	addr, stop := serve(t, mdns.HandlerFunc(s.Handle))
	defer stop()
	if r := ask(t, addr, "example.org", mdns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*mdns.A).A.String() != "9.9.9.9" {
		t.Fatalf("forwarded answer: %v", r.Answer)
	}
	if r := ask(t, addr, "radio.vtuner.com", mdns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*mdns.A).A.String() != "10.1.2.3" {
		t.Fatalf("intercepted answer: %v", r.Answer)
	}
}

func TestRestrictForwardingRefusesUnknownClients(t *testing.T) {
	up, stopUp := upstream(t)
	defer stopUp()
	s := New("*.vtuner.com", "127.0.0.1", "10.1.2.3", true, "")
	s.UpstreamPort = up
	addr, stop := serve(t, mdns.HandlerFunc(s.Handle))
	defer stop()
	if r := ask(t, addr, "example.org", mdns.TypeA); r.Rcode != mdns.RcodeRefused || len(r.Answer) != 0 {
		t.Fatalf("unknown client should be refused, got rcode %d answers %d", r.Rcode, len(r.Answer))
	}
	// Intercepted names are always answered: that is the point of the service.
	if r := ask(t, addr, "radio.vtuner.com", mdns.TypeA); len(r.Answer) != 1 {
		t.Fatal("intercept must still work for an unknown client")
	}
	// Reaching the web side (loginxml) makes the address a known client.
	s.NoteWebClient("127.0.0.1")
	if r := ask(t, addr, "example.org", mdns.TypeA); r.Rcode != mdns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("a known client should be forwarded, got rcode %d", r.Rcode)
	}
}

func TestKnownClientExpiresAndAllowListWorks(t *testing.T) {
	s := New("", "", "", true, " 192.0.2.7 , 192.0.2.8")
	if !s.clientAllowed("192.0.2.8") || s.clientAllowed("192.0.2.9") {
		t.Fatal("allow list")
	}
	s.mu.Lock()
	s.known["198.51.100.1"] = time.Now().Add(-25 * time.Hour)
	s.known["198.51.100.2"] = time.Now().Add(-23 * time.Hour)
	s.mu.Unlock()
	if s.clientAllowed("198.51.100.1") || !s.clientAllowed("198.51.100.2") {
		t.Fatal("24 hour expiry")
	}
}

func TestUpstreamDownGivesNotImplemented(t *testing.T) {
	s := New("", "127.0.0.1", "", false, "")
	s.UpstreamPort = "1" // nothing listens
	addr, stop := serve(t, mdns.HandlerFunc(s.Handle))
	defer stop()
	if r := ask(t, addr, "example.org", mdns.TypeA); r.Rcode != mdns.RcodeNotImplemented {
		t.Fatalf("rcode %d", r.Rcode)
	}
}

func TestKnownClientCachePrunesExpiredEntriesOnWebTraffic(t *testing.T) {
	s := New("", "", "", true, "")
	s.known["192.0.2.1"] = time.Now().Add(-25 * time.Hour)
	s.NoteWebClient("192.0.2.2")
	if _, ok := s.known["192.0.2.1"]; ok {
		t.Fatal("expired entry retained")
	}
	if !s.clientAllowed("192.0.2.2") {
		t.Fatal("new client not admitted")
	}
}

func TestKnownClientCacheCapsWithoutEvictingOrExtendingOtherClients(t *testing.T) {
	s := New("", "", "", true, "203.0.113.9")
	old := time.Now().Add(-23 * time.Hour)
	for i := 0; i < 4096; i++ {
		s.known[net.IPv4(10, byte(i>>8), byte(i), 1).String()] = old
	}
	s.NoteWebClient("192.0.2.1")
	if len(s.known) != 4096 {
		t.Fatalf("cache grew to %d", len(s.known))
	}
	if s.clientAllowed("192.0.2.1") {
		t.Fatal("overflow client got forwarding")
	}
	s.NoteWebClient("10.0.0.1")
	if !s.known["10.0.0.1"].After(old) {
		t.Fatal("full cache prevents existing client refresh")
	}
	if s.known["10.0.1.1"] != old {
		t.Fatal("refresh extended other clients")
	}
	if !s.clientAllowed("203.0.113.9") {
		t.Fatal("cap blocked explicit allow list")
	}
}

func TestKnownClientCacheRejectsNonIPAddresses(t *testing.T) {
	s := New("", "", "", true, "")
	for _, addr := range []string{"", " ", "not-an-ip", "192.0.2.1:80"} {
		s.NoteWebClient(addr)
	}
	if len(s.known) != 0 {
		t.Fatal("cache retained non-IP addresses")
	}
	s.NoteWebClient(" 192.0.2.1 ")
	if !s.clientAllowed("192.0.2.1") {
		t.Fatal("valid address not normalized")
	}
}

func TestExpiredKnownClientIsRefusedOnWireAndRemoved(t *testing.T) {
	up, stopUp := upstream(t)
	defer stopUp()
	s := New("*.vtuner.com", "127.0.0.1", "10.1.2.3", true, "")
	s.UpstreamPort = up
	s.known["127.0.0.1"] = time.Now().Add(-25 * time.Hour)
	addr, stop := serve(t, mdns.HandlerFunc(s.Handle))
	defer stop()
	if r := ask(t, addr, "example.org", mdns.TypeA); r.Rcode != mdns.RcodeRefused {
		t.Fatal("expired client forwarded")
	}
	s.mu.Lock()
	_, remains := s.known["127.0.0.1"]
	s.mu.Unlock()
	if remains {
		t.Fatal("expired queried entry retained")
	}
	s.NoteWebClient("127.0.0.1")
	if r := ask(t, addr, "example.org", mdns.TypeA); len(r.Answer) != 1 {
		t.Fatal("fresh login did not restore forwarding")
	}
}

func TestConcurrentWebTrafficCannotExceedClientCap(t *testing.T) {
	s := New("", "", "", true, "")
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				addr := net.IPv4(10, byte(g), byte(i>>8), byte(i)).String()
				s.NoteWebClient(addr)
				s.clientAllowed(addr)
			}
		}(g)
	}
	wg.Wait()
	if len(s.known) != 4096 {
		t.Fatalf("concurrent cache size=%d", len(s.known))
	}
}

func TestLearnedClientCanonicalAddressAndZone(t *testing.T) {
	s := New("", "", "", true, "")
	s.NoteWebClient("fe80::1%eth0")
	if !s.clientAllowed("fe80:0:0:0:0:0:0:1%eth0") || s.clientAllowed("fe80::1%eth1") {
		t.Fatal("link-local zone identity lost")
	}
	s.NoteWebClient("::ffff:192.0.2.1")
	if !s.clientAllowed("192.0.2.1") {
		t.Fatal("IPv4-mapped canonical mismatch")
	}
}
func TestIPv6ChurnCannotFillGlobalCacheOrAuthorizeNeighbours(t *testing.T) {
	s := New("", "", "", true, "")
	for i := 1; i <= 5000; i++ {
		s.NoteWebClient(fmt.Sprintf("2001:db8::%x", i))
	}
	if len(s.known) > 64 {
		t.Fatalf("one prefix retained %d clients", len(s.known))
	}
	if s.clientAllowed("2001:db8::ffff") {
		t.Fatal("unseen neighbour authorized")
	}
	s.NoteWebClient("2001:db8:1::1")
	if !s.clientAllowed("2001:db8:1::1") {
		t.Fatal("one prefix blocked another")
	}
}
func TestFullCacheReclaimsExpiryImmediatelyAndLogsDropsWithLimit(t *testing.T) {
	s := New("", "", "", true, "")
	for i := 0; i < 4096; i++ {
		s.NoteWebClient(net.IPv4(10, byte(i>>8), byte(i), 1).String())
	}
	var output bytes.Buffer
	saved := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(saved)
	s.NoteWebClient("192.0.2.1")
	s.NoteWebClient("192.0.2.2")
	if strings.Count(output.String(), "cache full") != 1 {
		t.Fatal("capacity drop absent or log not rate limited")
	}
	// Model a previously admitted client expiring just before this insertion.
	s.known["10.0.0.1"] = time.Now().Add(-25 * time.Hour)
	s.nextExpiry = time.Now().Add(-time.Second)
	s.NoteWebClient("192.0.2.3")
	if !s.clientAllowed("192.0.2.3") || len(s.known) != 4096 {
		t.Fatal("full cache did not reclaim expiry immediately")
	}
}

func TestIPv6PrefixSlotsFreedByExpiryWithoutGrantingSubnet(t *testing.T) {
	s := New("", "", "", true, "")
	for i := 1; i <= 64; i++ {
		s.NoteWebClient(fmt.Sprintf("2001:db8::%x", i))
	}
	s.known["2001:db8::1"] = time.Now().Add(-25 * time.Hour)
	s.nextExpiry = time.Now().Add(-time.Second)
	s.NoteWebClient("2001:db8::ff")
	if !s.clientAllowed("2001:db8::ff") || s.clientAllowed("2001:db8::1") || s.clientAllowed("2001:db8::ffff") {
		t.Fatal("prefix expiry changed exact-IP grants")
	}
	if s.prefixCounts["2001:db8::/64%"] != 64 {
		t.Fatal("prefix slot accounting drift")
	}
}
