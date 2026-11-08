package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fields are tagged omitempty so that rewriting the config file (-genpass)
// only writes the settings that were present before.
type ClientConfig struct {
	Fqdn          string `json:",omitempty"`
	Ipv6Interface string `json:",omitempty"`
	PasswordHash  string `json:",omitempty"`
	Key           string `json:",omitempty"` // obsolete cleartext passphrase, rejected at startup
}

type Client struct {
	mu            sync.Mutex // serializes updates of this client (cache + nsupdate)
	fqdn          string
	ipv6Interface []byte // trailing bytes of the IPv6 address to override, 2 per group
	passwordHash  *passwordHash
	ipv4          string
	ipv6          string
}

type Config struct {
	Host           string         `json:",omitempty"` // obsolete: the server always binds to listenHost; ignored with a warning
	Port           int            `json:",omitempty"`
	NsupdateTTL    int            `json:",omitempty"`
	NsupdateCmd    string         `json:",omitempty"`
	NsupdateKey    string         `json:",omitempty"`
	NsupdateServer string         `json:",omitempty"`
	TrustProxy     *bool          `json:",omitempty"` // take the client IP from the X-Real-Ip header; nil means default (true)
	Debug          bool           `json:",omitempty"` // log debug messages
	Clients        []ClientConfig `json:",omitempty"`
}

// listenHost is the only address the HTTP server binds to. sddns must run
// behind a reverse proxy that terminates TLS, so it is never exposed directly.
const listenHost = "127.0.0.1"

var gConfig = Config{Port: 3200, NsupdateTTL: 300, NsupdateCmd: "/usr/bin/nsupdate", NsupdateServer: "localhost"}
var gClients = make(map[string]*Client)

// gDryRun skips executing nsupdate and only logs the updates (-dryrun flag).
var gDryRun bool

// gLogLevel controls the log level of the default logger; raised to Debug by the Debug config option.
var gLogLevel = new(slog.LevelVar)

func initLogging() {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: gLogLevel})
	slog.SetDefault(slog.New(handler))
}

// fatal logs an error and terminates the program.
func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

// readConfig reads the config file into cfg. With strict set, unknown fields
// are an error (used before rewriting the file, so nothing is silently dropped).
func readConfig(filename string, cfg *Config, strict bool) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	dec := json.NewDecoder(strings.NewReader(string(data)))
	if strict {
		dec.DisallowUnknownFields()
	}

	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("syntax error: %w", err)
	}

	return nil
}

// saveConfig writes cfg to filename atomically, keeping the file's permissions.
func saveConfig(filename string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	mode := os.FileMode(0600)
	if st, err := os.Stat(filename); err == nil {
		mode = st.Mode().Perm()
	}

	tmp, err := os.CreateTemp(filepath.Dir(filename), ".sddns-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmpName, filename)
	}
	if err != nil {
		os.Remove(tmpName)
		return err
	}

	return nil
}

// Password hashes are stored as "pbkdf2-sha256$<iterations>$<salt>$<hash>"
// with salt and hash in unpadded standard base64.
const (
	hashScheme     = "pbkdf2-sha256"
	hashIterations = 100000
	hashSaltLen    = 16
	hashKeyLen     = 32
)

var b64 = base64.RawStdEncoding

type passwordHash struct {
	iter int
	salt []byte
	key  []byte
}

// gDummyHash is checked for unknown FQDNs so their response time matches known ones.
var gDummyHash = &passwordHash{iter: hashIterations, salt: make([]byte, hashSaltLen), key: make([]byte, hashKeyLen)}

func hashPassword(password string) (string, error) {
	salt := make([]byte, hashSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := pbkdf2.Key(sha256.New, password, salt, hashIterations, hashKeyLen)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s$%d$%s$%s", hashScheme, hashIterations, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

func parsePasswordHash(s string) (*passwordHash, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return nil, fmt.Errorf("unsupported format, expected %s$<iterations>$<salt>$<hash>", hashScheme)
	}

	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return nil, fmt.Errorf("invalid iteration count '%s'", parts[1])
	}

	salt, err := b64.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return nil, fmt.Errorf("invalid salt")
	}

	key, err := b64.DecodeString(parts[3])
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("invalid hash")
	}

	return &passwordHash{iter: iter, salt: salt, key: key}, nil
}

func (h *passwordHash) verify(password string) bool {
	key, err := pbkdf2.Key(sha256.New, password, h.salt, h.iter, len(h.key))
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(key, h.key) == 1
}

// generatePassword creates a random password for fqdn, stores its hash in the
// config file (adding the client if needed) and prints the cleartext password.
func generatePassword(cfgFile, fqdn string) error {
	var cfg Config // no defaults, so only existing settings are written back
	if err := readConfig(cfgFile, &cfg, true); err != nil {
		return err
	}

	password := rand.Text()
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}

	idx := -1
	for i := range cfg.Clients {
		if cfg.Clients[i].Fqdn == fqdn {
			idx = i
			break
		}
	}

	added := idx < 0
	if added {
		cfg.Clients = append(cfg.Clients, ClientConfig{Fqdn: fqdn})
		idx = len(cfg.Clients) - 1
	}

	cfg.Clients[idx].PasswordHash = hash
	cfg.Clients[idx].Key = ""
	cfg.Host = "" // obsolete setting, dropped when the file is rewritten

	if err := saveConfig(cfgFile, &cfg); err != nil {
		return err
	}

	if added {
		fmt.Printf("Added client %s to %s.\n", fqdn, cfgFile)
	} else {
		fmt.Printf("Replaced password of client %s in %s.\n", fqdn, cfgFile)
	}
	fmt.Printf("Password: %s\n", password)
	fmt.Println("The password is not stored in cleartext and cannot be shown again.")
	fmt.Println("Restart sddns to apply the change.")

	return nil
}

func genpassHint(fqdn, cfgFile string) string {
	return fmt.Sprintf("%s -genpass %s %s", filepath.Base(os.Args[0]), fqdn, cfgFile)
}

// parseIpv6Interface parses the trailing groups of an IPv6 address given as
// colon separated hex groups (e.g. "211:32ff:fe12:3456") into bytes.
// An empty string disables interface merging.
func parseIpv6Interface(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}

	groups := strings.Split(s, ":")
	if len(groups) > 7 {
		return nil, fmt.Errorf("too many groups (%d), at most 7 allowed", len(groups))
	}

	buf := make([]byte, 0, 2*len(groups))
	for _, g := range groups {
		if g == "" {
			return nil, fmt.Errorf("empty group ('::' is not supported)")
		}
		v, err := strconv.ParseUint(g, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid group '%s'", g)
		}
		buf = append(buf, byte(v>>8), byte(v))
	}

	return buf, nil
}

// mergeIpv6 parses an IPv6 address in any valid notation (including
// compressed "::" form) or an IPv6 prefix in CIDR notation (e.g.
// "2001:db8:1:2::/64") and replaces its trailing bytes with iface.
// For a prefix, the prefix bits are kept and iface fills the remaining bits;
// iface must cover all of them.
func mergeIpv6(addr string, iface []byte) (string, error) {
	if !strings.Contains(addr, "/") {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() != nil {
			return "", fmt.Errorf("not an IPv6 address")
		}

		merged := make(net.IP, net.IPv6len)
		copy(merged, ip.To16())
		copy(merged[net.IPv6len-len(iface):], iface)
		return merged.String(), nil
	}

	_, ipnet, err := net.ParseCIDR(addr)
	if err != nil {
		return "", fmt.Errorf("not an IPv6 address or prefix")
	}
	prefixLen, bits := ipnet.Mask.Size()
	if bits != 8*net.IPv6len || ipnet.IP.To4() != nil {
		return "", fmt.Errorf("not an IPv6 prefix")
	}

	if hostBits := bits - prefixLen; 8*len(iface) < hostBits {
		return "", fmt.Errorf("prefix /%d requires an Ipv6Interface of at least %d groups", prefixLen, (hostBits+15)/16)
	}

	// Align iface to the end of the address, then take the prefix bits from
	// the network address and all other bits from iface.
	full := make([]byte, net.IPv6len)
	copy(full[net.IPv6len-len(iface):], iface)

	merged := make(net.IP, net.IPv6len)
	for i := range merged {
		merged[i] = ipnet.IP[i]&ipnet.Mask[i] | full[i]&^ipnet.Mask[i]
	}

	return merged.String(), nil
}

// parseIpv4 validates an IPv4 address and returns it in canonical dotted form.
func parseIpv4(addr string) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("not an IPv4 address")
	}

	return ip.To4().String(), nil
}

// remoteIp returns the IP address of the requesting client for logging.
// trustProxy reports whether the X-Real-Ip header is honored. It defaults to
// true: the server only listens on localhost, so requests come from the reverse proxy.
func trustProxy() bool {
	return gConfig.TrustProxy == nil || *gConfig.TrustProxy
}

// The X-Real-Ip header is only honored if trustProxy() is true.
func remoteIp(req *http.Request) string {
	if trustProxy() {
		if ip := req.Header.Get("X-Real-Ip"); ip != "" {
			return ip
		}
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}

	return host
}

func initClients(cfgFile string) {
	for _, c := range gConfig.Clients {
		slog.Debug("configured client", "fqdn", c.Fqdn)
		iface, err := parseIpv6Interface(c.Ipv6Interface)
		if err != nil {
			fatal("invalid Ipv6Interface", "fqdn", c.Fqdn, "value", c.Ipv6Interface, "err", err)
		}

		if c.Key != "" {
			fatal("cleartext Key is no longer supported - generate a hashed password",
				"fqdn", c.Fqdn, "run", genpassHint(c.Fqdn, cfgFile))
		}
		if c.PasswordHash == "" {
			fatal("no PasswordHash configured for client", "fqdn", c.Fqdn, "run", genpassHint(c.Fqdn, cfgFile))
		}
		hash, err := parsePasswordHash(c.PasswordHash)
		if err != nil {
			fatal("invalid PasswordHash", "fqdn", c.Fqdn, "err", err)
		}

		client := new(Client)
		client.fqdn = c.Fqdn
		client.ipv6Interface = iface
		client.passwordHash = hash
		gClients[c.Fqdn] = client
	}
}

// checkNsupdateConfig verifies that the settings needed to run nsupdate are present.
func checkNsupdateConfig() {
	if gConfig.NsupdateKey == "" {
		fatal("NsupdateKey must be set to the TSIG key file used by nsupdate")
	}

	if _, err := os.Stat(gConfig.NsupdateKey); err != nil {
		fatal("cannot access NsupdateKey file", "err", err)
	}
}

// nsupdateScript returns the nsupdate commands that replace the record of type
// rrtype ("A" or "AAAA") for fqdn with addr.
func nsupdateScript(fqdn, rrtype, addr string) string {
	rr := strings.ToLower(rrtype)
	script := fmt.Sprintf("server %s\n", gConfig.NsupdateServer)
	script += fmt.Sprintf("del %s in %s\n", fqdn, rr)
	script += fmt.Sprintf("add %s %d in %s %s\n", fqdn, gConfig.NsupdateTTL, rr, addr)
	script += "send\n"
	return script
}

// updateRecord sets the record of type rrtype for fqdn to addr using nsupdate.
// In dry run mode it only logs the nsupdate script.
func updateRecord(fqdn, rrtype, addr string) bool {
	script := nsupdateScript(fqdn, rrtype, addr)

	if gDryRun {
		slog.Info("dry run: nsupdate not executed", "fqdn", fqdn, "type", rrtype, "addr", addr, "script", script)
		return true
	}

	fp, err := os.CreateTemp("", "nsupdate")
	if err != nil {
		slog.Error("cannot create nsupdate script file", "err", err)
		return false
	}
	defer os.Remove(fp.Name())

	_, err = fp.WriteString(script)
	if cerr := fp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		slog.Error("failed writing nsupdate script file", "err", err)
		return false
	}

	return runNsupdate(fp.Name())
}

func runNsupdate(script string) bool {
	cmd := exec.Command(gConfig.NsupdateCmd, "-k", gConfig.NsupdateKey, script)
	out, err := cmd.CombinedOutput()

	if err != nil {
		slog.Error("nsupdate failed", "err", err, "output", string(out))
		return false
	}

	slog.Debug("nsupdate succeeded", "output", string(out))

	return true
}

func serverUrl() {
	httpServer := &http.Server{
		Addr:           net.JoinHostPort(listenHost, strconv.Itoa(gConfig.Port)),
		Handler:        nil,
		ReadTimeout:    20 * time.Second,
		WriteTimeout:   20 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	http.HandleFunc("/update", handleUrl)

	slog.Info("listening", "addr", httpServer.Addr)
	fatal("http server exited", "err", httpServer.ListenAndServe())
}

func handleUrl(resp http.ResponseWriter, req *http.Request) {
	ip := remoteIp(req)

	q := req.URL.Query()

	v := q["fqdn"]

	if len(v) == 0 || v[0] == "" {
		slog.Error("request without fqdn", "client", ip)
		io.WriteString(resp, "no FQDN - use ?fqdn=<fqdn>\n")
		return
	}

	fqdn := v[0]

	// Never log the query string: it contains the passphrase.
	slog.Info("request", "path", req.URL.Path, "client", ip, "fqdn", fqdn)

	v = q["pass"]

	if len(v) == 0 || v[0] == "" {
		slog.Error("request without passphrase", "fqdn", fqdn, "client", ip)
		io.WriteString(resp, "no passphrase - use ?pass=<pass>\n")
		return
	}

	pass := v[0]

	client := gClients[fqdn]

	// Always run the hash check, also for unknown FQDNs, so timing does not reveal configured names.
	hash := gDummyHash
	if client != nil {
		hash = client.passwordHash
	}

	if !hash.verify(pass) || client == nil {
		slog.Error("invalid fqdn or passphrase", "fqdn", fqdn, "client", ip)
		io.WriteString(resp, "invalid FQDN or passphrase\n")
		return
	}

	// Serialize updates per client so cache and DNS stay consistent.
	client.mu.Lock()
	defer client.mu.Unlock()

	res := true

	slog.Info("validated update request", "fqdn", fqdn, "client", ip)

	ipv4 := ""
	v = q["ipv4"]
	if len(v) > 0 {
		ipv4 = v[0]
	}

	if ipv4 != "" {
		parsed, err := parseIpv4(ipv4)
		if err != nil {
			slog.Error("invalid IPv4 address", "fqdn", fqdn, "client", ip, "value", ipv4, "err", err)
			res = false
			ipv4 = ""
		} else {
			ipv4 = parsed
		}
	}

	if ipv4 != "" && ipv4 != client.ipv4 {
		slog.Debug("updating A record", "fqdn", fqdn, "ipv4", ipv4)
		if updateRecord(fqdn, "A", ipv4) {
			slog.Info("updated A record", "fqdn", fqdn, "ipv4", ipv4, "dry_run", gDryRun)
			client.ipv4 = ipv4
		} else {
			res = false
		}
	}

	ipv6 := ""
	v = q["ipv6"]
	if len(v) > 0 {
		ipv6 = v[0]
	}

	if ipv6 != "" {
		merged, err := mergeIpv6(ipv6, client.ipv6Interface)
		if err != nil {
			slog.Error("invalid IPv6 address", "fqdn", fqdn, "client", ip, "value", ipv6, "err", err)
			res = false
			ipv6 = ""
		} else {
			ipv6 = merged
		}
	}

	if ipv6 != "" && ipv6 != client.ipv6 {
		slog.Debug("updating AAAA record", "fqdn", fqdn, "ipv6", ipv6)
		if updateRecord(fqdn, "AAAA", ipv6) {
			slog.Info("updated AAAA record", "fqdn", fqdn, "ipv6", ipv6, "dry_run", gDryRun)
			client.ipv6 = ipv6
		} else {
			res = false
		}
	}

	if res {
		io.WriteString(resp, "ok\n")
	} else {
		io.WriteString(resp, "fail\n")
	}
}

func main() {
	initLogging()

	genpass := flag.String("genpass", "", "generate a random password for client `FQDN`, store its hash in the config file and print the password")
	flag.BoolVar(&gDryRun, "dryrun", false, "do not execute nsupdate, only log the updates that would be done")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-dryrun] [-genpass FQDN] <config file>\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	cfgFile := flag.Arg(0)

	if *genpass != "" {
		if err := generatePassword(cfgFile, *genpass); err != nil {
			fatal("failed to generate password", "file", cfgFile, "fqdn", *genpass, "err", err)
		}
		return
	}

	if err := readConfig(cfgFile, &gConfig, false); err != nil {
		fatal("failed to read config file", "file", cfgFile, "err", err)
	}

	if gConfig.Debug {
		gLogLevel.Set(slog.LevelDebug)
	}

	if gConfig.Host != "" {
		slog.Warn("config option Host is no longer supported and is ignored", "host", gConfig.Host, "listen", listenHost)
	}

	initClients(cfgFile)

	if len(gClients) == 0 {
		fatal("no clients configured", "file", cfgFile)
	}

	if gDryRun {
		slog.Warn("dry run mode: nsupdate is not executed, DNS records are not changed")
	} else {
		checkNsupdateConfig()
	}

	serverUrl()
}
