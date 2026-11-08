package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// setup resets global state, captures log output and restores everything after the test.
func setup(t *testing.T) *bytes.Buffer {
	t.Helper()

	oldConfig, oldClients, oldDryRun, oldLogger := gConfig, gClients, gDryRun, slog.Default()
	t.Cleanup(func() {
		gConfig, gClients, gDryRun = oldConfig, oldClients, oldDryRun
		slog.SetDefault(oldLogger)
	})

	gConfig = Config{Port: 3200, NsupdateTTL: 300, NsupdateCmd: "/nonexistent/nsupdate", NsupdateServer: "localhost"}
	gClients = make(map[string]*Client)
	gDryRun = false

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return &buf
}

// addClient registers a client with the given password and IPv6 interface.
func addClient(t *testing.T, fqdn, password, ipv6Interface string) *Client {
	t.Helper()

	s, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	h, err := parsePasswordHash(s)
	if err != nil {
		t.Fatal(err)
	}
	iface, err := parseIpv6Interface(ipv6Interface)
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{fqdn: fqdn, passwordHash: h, ipv6Interface: iface}
	gClients[fqdn] = c
	return c
}

// request calls the update handler with the given query parameters and returns the response body.
func request(params map[string]string) string {
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	r := httptest.NewRequest("GET", "/update?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	handleUrl(w, r)
	return strings.TrimSpace(w.Body.String())
}

func TestParseIpv4(t *testing.T) {
	valid := map[string]string{
		"203.0.113.7": "203.0.113.7",
		"0.0.0.0":     "0.0.0.0",
	}
	for in, want := range valid {
		got, err := parseIpv4(in)
		if err != nil || got != want {
			t.Errorf("parseIpv4(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	invalid := []string{
		"",
		"203.0.113",
		"203.0.113.256",
		"2001:db8::1",
		"::ffff:zz",
		"203.0.113.7 ",
		"203.0.113.7\nadd www.example.org 300 in a 198.51.100.1",
		"example.org",
	}
	for _, in := range invalid {
		if got, err := parseIpv4(in); err == nil {
			t.Errorf("parseIpv4(%q) = %q, want error", in, got)
		}
	}
}

func TestParseIpv6Interface(t *testing.T) {
	if b, err := parseIpv6Interface(""); err != nil || b != nil {
		t.Errorf("empty: got %v, %v; want nil, nil", b, err)
	}

	b, err := parseIpv6Interface("211:32ff:fe12:3456")
	want := []byte{0x02, 0x11, 0x32, 0xff, 0xfe, 0x12, 0x34, 0x56}
	if err != nil || !bytes.Equal(b, want) {
		t.Errorf("got %x, %v; want %x", b, err, want)
	}

	if b, err := parseIpv6Interface("1:2:3:4:5:6:7"); err != nil || len(b) != 14 {
		t.Errorf("7 groups: got %x, %v", b, err)
	}

	invalid := []string{"1:2:3:4:5:6:7:8", "::1", "1::2", "1:", "12345", "xyz", "1:2:g"}
	for _, in := range invalid {
		if _, err := parseIpv6Interface(in); err == nil {
			t.Errorf("parseIpv6Interface(%q): want error", in)
		}
	}
}

func TestMergeIpv6(t *testing.T) {
	iface, _ := parseIpv6Interface("211:32ff:fe12:3456")
	iface5, _ := parseIpv6Interface("7:211:32ff:fe12:3456")

	cases := []struct {
		addr  string
		iface []byte
		want  string
	}{
		{"2001:db8:1234:5600:abcd:ef01:2345:6789", iface, "2001:db8:1234:5600:211:32ff:fe12:3456"},
		{"2001:db8:1234:5600::1", iface, "2001:db8:1234:5600:211:32ff:fe12:3456"},
		{"2001:db8::1", nil, "2001:db8::1"},
		{"2001:0db8:0000:0000:0000:0000:0000:0001", nil, "2001:db8::1"},
		// prefixes in CIDR notation
		{"2001:9e8:8cc2:4900::/64", iface, "2001:9e8:8cc2:4900:211:32ff:fe12:3456"},
		{"2001:9e8:8cc2:4900:1:2:3:4/64", iface, "2001:9e8:8cc2:4900:211:32ff:fe12:3456"}, // host bits ignored
		{"2001:9e8:8cc2:4900::/56", iface5, "2001:9e8:8cc2:4907:211:32ff:fe12:3456"},      // interface sets subnet ID
		{"2001:db8::1/128", nil, "2001:db8::1"},
	}
	for _, c := range cases {
		got, err := mergeIpv6(c.addr, c.iface)
		if err != nil || got != c.want {
			t.Errorf("mergeIpv6(%q) = %q, %v; want %q", c.addr, got, err, c.want)
		}
	}

	invalid := []string{
		"", "203.0.113.7", "::ffff:203.0.113.7", "2001:db8::1\nsend", "2001:db8:::1",
		"203.0.113.0/24", "2001:db8::/129", "2001:db8::/", "2001:db8::/64/64", "2001:db8::/x",
		"2001:db8::/56", // interface (4 groups) does not cover the 72 host bits
	}
	for _, in := range invalid {
		if _, err := mergeIpv6(in, iface); err == nil {
			t.Errorf("mergeIpv6(%q): want error", in)
		}
	}

	// A prefix without Ipv6Interface would give the bare network address.
	if got, err := mergeIpv6("2001:9e8:8cc2:4900::/64", nil); err == nil {
		t.Errorf("prefix without interface: got %q, want error", got)
	}
}

func TestHandlerIpv6Prefix(t *testing.T) {
	logs := setup(t)
	gDryRun = true
	c := addClient(t, "h.example.org", "secret", "211:32ff:fe12:3456")

	got := request(map[string]string{"fqdn": "h.example.org", "pass": "secret", "ipv6": "2001:9e8:8cc2:4900::/64"})
	if got != "ok" {
		t.Fatalf("got %q, want ok\n%s", got, logs)
	}
	if c.ipv6 != "2001:9e8:8cc2:4900:211:32ff:fe12:3456" {
		t.Errorf("cached ipv6 = %q", c.ipv6)
	}
}

func TestPasswordHash(t *testing.T) {
	s, err := hashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^pbkdf2-sha256\$100000\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`).MatchString(s) {
		t.Errorf("unexpected hash format: %s", s)
	}

	h, err := parsePasswordHash(s)
	if err != nil {
		t.Fatal(err)
	}
	if !h.verify("correct horse") {
		t.Error("correct password rejected")
	}
	if h.verify("correct horse ") || h.verify("") {
		t.Error("wrong password accepted")
	}

	if s2, _ := hashPassword("correct horse"); s2 == s {
		t.Error("same hash for two calls - salt not random")
	}
}

func TestParsePasswordHashInvalid(t *testing.T) {
	invalid := []string{
		"",
		"secret",
		"bcrypt$10$abc$def",
		"pbkdf2-sha256$100000$abc",
		"pbkdf2-sha256$x$AAAA$AAAA",
		"pbkdf2-sha256$0$AAAA$AAAA",
		"pbkdf2-sha256$100000$$AAAA",
		"pbkdf2-sha256$100000$AAAA$",
		"pbkdf2-sha256$100000$!!!!$AAAA",
	}
	for _, in := range invalid {
		if _, err := parsePasswordHash(in); err == nil {
			t.Errorf("parsePasswordHash(%q): want error", in)
		}
	}
}

func TestGeneratedPasswordFormat(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "c.json")
	writeFile(t, cfg, `{"Clients": [{"Fqdn": "a.example.org"}]}`)

	out := captureStdout(t, func() {
		if err := generatePassword(cfg, "a.example.org"); err != nil {
			t.Fatal(err)
		}
	})

	pw := passwordFrom(t, out)
	if !regexp.MustCompile(`^[A-Z2-7]{26}$`).MatchString(pw) {
		t.Errorf("unexpected password format: %q", pw)
	}
}

func TestNsupdateScript(t *testing.T) {
	setup(t)
	gConfig.NsupdateServer = "ns1.example.org"
	gConfig.NsupdateTTL = 60

	got := nsupdateScript("h.example.org", "AAAA", "2001:db8::1")
	want := "server ns1.example.org\n" +
		"del h.example.org in aaaa\n" +
		"add h.example.org 60 in aaaa 2001:db8::1\n" +
		"send\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRemoteIp(t *testing.T) {
	setup(t)

	r := httptest.NewRequest("GET", "/update", nil) // RemoteAddr is 192.0.2.1:1234
	r.Header.Set("X-Real-Ip", "203.0.113.9")

	if got := remoteIp(r); got != "203.0.113.9" {
		t.Errorf("TrustProxy default: got %q, want header value", got)
	}

	off := false
	gConfig.TrustProxy = &off
	if got := remoteIp(r); got != "192.0.2.1" {
		t.Errorf("TrustProxy false: got %q, want connection address", got)
	}

	gConfig.TrustProxy = nil
	r.Header.Del("X-Real-Ip")
	if got := remoteIp(r); got != "192.0.2.1" {
		t.Errorf("no header: got %q, want connection address", got)
	}
}

func TestHandlerRejects(t *testing.T) {
	logs := setup(t)
	addClient(t, "h.example.org", "secret", "")

	cases := []struct {
		name   string
		params map[string]string
		prefix string
	}{
		{"missing fqdn", map[string]string{"pass": "secret"}, "no FQDN"},
		{"missing pass", map[string]string{"fqdn": "h.example.org"}, "no passphrase"},
		{"wrong pass", map[string]string{"fqdn": "h.example.org", "pass": "wrong"}, "invalid FQDN or passphrase"},
		{"unknown fqdn", map[string]string{"fqdn": "x.example.org", "pass": "secret"}, "invalid FQDN or passphrase"},
	}
	for _, c := range cases {
		if got := request(c.params); !strings.HasPrefix(got, c.prefix) {
			t.Errorf("%s: got %q, want prefix %q", c.name, got, c.prefix)
		}
	}

	if strings.Contains(logs.String(), "secret") {
		t.Errorf("password appears in log:\n%s", logs)
	}
	if !strings.Contains(logs.String(), `msg="invalid fqdn or passphrase" fqdn=h.example.org client=192.0.2.1`) {
		t.Errorf("failed login not logged with client IP:\n%s", logs)
	}
}

func TestHandlerNoAddresses(t *testing.T) {
	setup(t)
	addClient(t, "h.example.org", "secret", "")

	if got := request(map[string]string{"fqdn": "h.example.org", "pass": "secret"}); got != "ok" {
		t.Errorf("got %q, want ok", got)
	}
}

func TestHandlerInvalidAddresses(t *testing.T) {
	logs := setup(t)
	gDryRun = true
	c := addClient(t, "h.example.org", "secret", "")

	for _, p := range []map[string]string{
		{"ipv4": "203.0.113.7\nadd www.example.org 300 in a 198.51.100.1"},
		{"ipv4": "2001:db8::1"},
		{"ipv6": "2001:db8::1\nsend"},
		{"ipv6": "203.0.113.7"},
	} {
		p["fqdn"], p["pass"] = "h.example.org", "secret"
		if got := request(p); got != "fail" {
			t.Errorf("%v: got %q, want fail", p, got)
		}
	}

	if c.ipv4 != "" || c.ipv6 != "" {
		t.Errorf("cache updated by invalid input: ipv4=%q ipv6=%q", c.ipv4, c.ipv6)
	}
	if strings.Contains(logs.String(), "nsupdate not executed") {
		t.Errorf("update attempted for invalid input:\n%s", logs)
	}
}

func TestHandlerDryRunUpdatesAndCaches(t *testing.T) {
	logs := setup(t)
	gDryRun = true
	c := addClient(t, "h.example.org", "secret", "211:32ff:fe12:3456")

	params := map[string]string{
		"fqdn": "h.example.org", "pass": "secret",
		"ipv4": "203.0.113.7", "ipv6": "2001:db8:1:2::1",
	}
	if got := request(params); got != "ok" {
		t.Fatalf("got %q, want ok", got)
	}

	if c.ipv4 != "203.0.113.7" {
		t.Errorf("cached ipv4 = %q", c.ipv4)
	}
	if c.ipv6 != "2001:db8:1:2:211:32ff:fe12:3456" {
		t.Errorf("cached ipv6 = %q (interface not merged?)", c.ipv6)
	}
	if !strings.Contains(logs.String(), `add h.example.org 300 in aaaa 2001:db8:1:2:211:32ff:fe12:3456`) {
		t.Errorf("merged AAAA script not logged:\n%s", logs)
	}
	if n := strings.Count(logs.String(), "nsupdate not executed"); n != 2 {
		t.Errorf("got %d updates, want 2", n)
	}

	// Same addresses again (IPv6 with a different interface part): cache hit, no update.
	params["ipv6"] = "2001:db8:1:2:aaaa:bbbb:cccc:dddd"
	if got := request(params); got != "ok" {
		t.Fatalf("second request: got %q, want ok", got)
	}
	if n := strings.Count(logs.String(), "nsupdate not executed"); n != 2 {
		t.Errorf("cache miss on unchanged addresses: %d updates, want 2", n)
	}

	// Changed IPv4: exactly one more update.
	params["ipv4"] = "203.0.113.8"
	request(params)
	if n := strings.Count(logs.String(), "nsupdate not executed"); n != 3 {
		t.Errorf("got %d updates after IPv4 change, want 3", n)
	}
}

func TestHandlerNsupdateFailure(t *testing.T) {
	logs := setup(t)
	c := addClient(t, "h.example.org", "secret", "")

	got := request(map[string]string{"fqdn": "h.example.org", "pass": "secret", "ipv4": "203.0.113.7"})
	if got != "fail" {
		t.Errorf("got %q, want fail", got)
	}
	if c.ipv4 != "" {
		t.Errorf("cache updated although nsupdate failed: %q", c.ipv4)
	}
	if !strings.Contains(logs.String(), `msg="nsupdate failed"`) {
		t.Errorf("nsupdate failure not logged:\n%s", logs)
	}
}

func TestGeneratePasswordAddsClient(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "c.json")
	writeFile(t, cfg, `{"Port": 3201, "NsupdateKey": "/etc/bind/ddns.key", "Clients": [{"Fqdn": "a.example.org", "Ipv6Interface": "1:2"}]}`)

	out := captureStdout(t, func() {
		if err := generatePassword(cfg, "b.example.org"); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Added client b.example.org") {
		t.Errorf("unexpected output: %s", out)
	}

	loaded := loadConfig(t, cfg)
	if loaded.Port != 3201 || loaded.NsupdateKey != "/etc/bind/ddns.key" {
		t.Errorf("settings not kept: %+v", loaded)
	}
	if len(loaded.Clients) != 2 || loaded.Clients[0].Ipv6Interface != "1:2" || loaded.Clients[0].PasswordHash != "" {
		t.Errorf("existing client changed: %+v", loaded.Clients)
	}
	checkPassword(t, loaded.Clients[1].PasswordHash, passwordFrom(t, out))
}

func TestGeneratePasswordReplacesAndMigrates(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "c.json")
	writeFile(t, cfg, `{"Host": "0.0.0.0", "Clients": [{"Fqdn": "a.example.org", "Key": "abcdefg"}]}`)

	out := captureStdout(t, func() {
		if err := generatePassword(cfg, "a.example.org"); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Replaced password of client a.example.org") {
		t.Errorf("unexpected output: %s", out)
	}

	data := readFile(t, cfg)
	if strings.Contains(data, "abcdefg") || strings.Contains(data, `"Key"`) {
		t.Errorf("cleartext Key not removed:\n%s", data)
	}
	if strings.Contains(data, "Host") {
		t.Errorf("obsolete Host not removed:\n%s", data)
	}

	loaded := loadConfig(t, cfg)
	if len(loaded.Clients) != 1 {
		t.Fatalf("got %d clients, want 1", len(loaded.Clients))
	}
	checkPassword(t, loaded.Clients[0].PasswordHash, passwordFrom(t, out))
}

func TestGeneratePasswordTrustProxy(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "c.json")

	writeFile(t, cfg, `{"TrustProxy": false, "Clients": [{"Fqdn": "a.example.org"}]}`)
	captureStdout(t, func() { generatePassword(cfg, "a.example.org") })
	if !strings.Contains(readFile(t, cfg), `"TrustProxy": false`) {
		t.Errorf("explicit TrustProxy false lost:\n%s", readFile(t, cfg))
	}

	writeFile(t, cfg, `{"Clients": [{"Fqdn": "a.example.org"}]}`)
	captureStdout(t, func() { generatePassword(cfg, "a.example.org") })
	if strings.Contains(readFile(t, cfg), "TrustProxy") {
		t.Errorf("default TrustProxy written out:\n%s", readFile(t, cfg))
	}
}

func TestGeneratePasswordRejectsUnknownFields(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "c.json")
	orig := `{"Clients": [], "Typo": 1}`
	writeFile(t, cfg, orig)

	if err := generatePassword(cfg, "a.example.org"); err == nil {
		t.Error("want error for unknown field")
	}
	if readFile(t, cfg) != orig {
		t.Error("config file modified despite error")
	}
}

// --- helpers ---

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func loadConfig(t *testing.T, name string) Config {
	t.Helper()
	var cfg Config
	if err := readConfig(name, &cfg, true); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()

	f()

	w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

func passwordFrom(t *testing.T, out string) string {
	t.Helper()
	m := regexp.MustCompile(`Password: (\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no password in output: %s", out)
	}
	return m[1]
}

func checkPassword(t *testing.T, hash, password string) {
	t.Helper()
	h, err := parsePasswordHash(hash)
	if err != nil {
		t.Fatalf("invalid stored hash %q: %v", hash, err)
	}
	if !h.verify(password) {
		t.Error("printed password does not match stored hash")
	}
}
