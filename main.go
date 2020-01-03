package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/mua69/gstakepool/log"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type ClientConfig struct {
	Fqdn string
	Key string
}

type Client struct {
	fqdn string
	key string
	ipv4 string
}

type Config struct{
	Host string
	Port int
	NsupdateTTL int
	NsupdateCmd string
	NsupdateKey string
	NsupdateServer string
	Fqdn string
	Key string
	Clients []ClientConfig
}

var gConfig = Config{Port:3200, NsupdateTTL:300, NsupdateCmd:"/usr/bin/nsupdate", NsupdateServer:"localhost"}
var gClients = make(map[string]*Client)

func readConfig(filename string) bool {
        data, err := ioutil.ReadFile(filename)

        if err != nil {
                fmt.Printf("Failed to open config file \"%s\": %s\n", filename, err.Error())
                return false
        }

        err = json.Unmarshal(data, &gConfig)
        if err != nil {
                fmt.Printf("Syntax error in config file %s: %v\n", filename, err)
                return false
        }

        return true
}

func initClients() {
	for _, c := range gConfig.Clients {
		log.Info(1, "Client: %s", c.Fqdn)
		client := new(Client)
		client.fqdn = c.Fqdn
		client.key = c.Key
		gClients[c.Fqdn] = client
	}
}

func createChallenge() string {
	buf := make([]byte, 32)

	n, err := rand.Read(buf)

	if err != nil {
		log.Error("Failed to create random challenge: %s", err.Error())
		return ""
	}

	if n != 32 {
		log.Error("Failed to create random challenge: unexpected byte count")
		return ""
	}

	return hex.EncodeToString(buf)
}

func createResponse(challenge, key string) string {
	mac := hmac.New(sha256.New, []byte(key))

	_, err := mac.Write([]byte(challenge))
	if err != nil {
		log.Error("Failed to create challenge response: %s", err.Error())
		return ""
	}

	sum := mac.Sum(nil)

	return hex.EncodeToString(sum)
}

func createNsupdateScriptIpv4(fqdn, ipv4 string) string {
	fp, err := ioutil.TempFile("", "nsupdate")

	if err != nil {
		log.Error("Cannot create nsupdate script file: %s", err.Error())
		return ""
	}

	script := fmt.Sprintf("server %s\n", gConfig.NsupdateServer)
	script += fmt.Sprintf("del %s in a\n", fqdn)
	script += fmt.Sprintf("add %s %d in a %s\n", fqdn, gConfig.NsupdateTTL, ipv4)
	script += "send\n"

	_, err = fp.WriteString(script)
	if err != nil {
		log.Error("Failed writing to nsupdate script file: %s", err.Error())
		fp.Close()
		os.Remove(fp.Name())
		return ""
	}

	err = fp.Close()

	if err != nil {
		log.Error("Failed writing to nsupdate script file: %s", err.Error())
		fp.Close()
		os.Remove(fp.Name())
		return ""
	}

	return fp.Name()
}

func runNsupdate(script string) bool {
	cmd := exec.Command(gConfig.NsupdateCmd, "-k", gConfig.NsupdateKey, script)
	out, err := cmd.CombinedOutput()

	if err != nil {
		log.Error("Failed to run nsupdate: %s", err.Error())
		return false
	}

	log.Info(1, "nsupdate output: %s", string(out))

	return true
}

func server() {
	adr := fmt.Sprintf("%s:%d", gConfig.Host, gConfig.Port)

	l, err := net.Listen("tcp", adr)

	if err != nil {
		log.Fatal("Failed to bind server: %s", err.Error())
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Error("Failed to accept connection: %s", err.Error())
		}
		go handleConnection(conn)
	}
}

func ioerror(err error) bool {
	if err != nil {
		log.Error("IO error: %s", err.Error())
		return true
	}

	return false
}

func handleConnection(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(20*time.Second))

	defer conn.Close()

	log.Info(0,"server: connection from: %s", conn.RemoteAddr().String())

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	fqdn, err := r.ReadString('\n')

	if ioerror(err) {
		return
	}

	fqdn = strings.Trim(fqdn, "\r\n")

	log.Info(1,"server: got fqdn: '%s'", fqdn)

	client := gClients[fqdn]

	if client == nil {
		log.Info(1,"server: client not found")
		return
	}

	challenge := createChallenge()

	if challenge == "" {
		return
	}

	_, err = w.WriteString(challenge + "\n")
	if ioerror(err) {
		return
	}
	w.Flush()

	expectedResponse := createResponse(challenge, client.key)

	if expectedResponse == "" {
		return
	}

	response, err := r.ReadString('\n')

	if ioerror(err) {
		return
	}

	response = strings.Trim(response, "\r\n")

	if response != expectedResponse {
		log.Info(1, "invalid response: %s, expected: %s", response, expectedResponse)
		return
	}

	ipv4, _, err := net.SplitHostPort(conn.RemoteAddr().String())

	if err != nil {
		log.Error("Cannot parse remote address: %s", err.Error())
		return
	}

	if ipv4 != client.ipv4 {
		log.Info(1, "Updating DNS entry: %s --> %s", fqdn, ipv4)
		script := createNsupdateScriptIpv4(fqdn, ipv4)

		if script == "" {
			return
		}

		if runNsupdate(script) {
			log.Info(0, "Updated DNS entry: %s --> %s", fqdn, ipv4)
			client.ipv4 = ipv4
		}

		os.Remove(script)
	}
}

func client() bool {
	adr := fmt.Sprintf("%s:%d", gConfig.Host, gConfig.Port)

	conn, err := net.Dial("tcp", adr)

	if err != nil {
		log.Error("Cannot connect to: %s", adr)
		return false
	}

	defer conn.Close()

	conn.SetDeadline(time.Now().Add(20*time.Second))

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	_, err = w.WriteString(gConfig.Fqdn + "\n")

	if ioerror(err) {
		return false
	}

	w.Flush()

	challenge, err := r.ReadString('\n')

	if ioerror(err) {
		return false
	}

	challenge = strings.Trim(challenge, "\r\n")
	log.Info(1, "client: challenge: '%s'", challenge)

	response := createResponse(challenge, gConfig.Key)
	log.Info(1, "client: response: '%s'", response)
	_, err = w.WriteString(response + "\n")

	if ioerror(err) {
		return false
	}

	w.Flush()


	return true
}

func serverUrl() {
	httpServer := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", gConfig.Host, gConfig.Port),
		Handler:        nil,
		ReadTimeout:    20 * time.Second,
		WriteTimeout:   20 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	http.HandleFunc("/update", handleUrl)

	log.Info(0,"http server exited: %s", httpServer.ListenAndServe())
}

func handleUrl(resp http.ResponseWriter, req *http.Request) {
	log.Info(0, "Request: %s", req.RequestURI)

	ip := retrieveRemoteIp(req)

	if ip == "" {
		log.Error("Cannot determine remote IP.")
		io.WriteString(resp, "no IP\n")
		return
	}

	q := req.URL.Query()

	v := q["fqdn"]

	if len(v) == 0 || v[0] == "" {
		log.Error("No FQDN specified.")
		io.WriteString(resp, "no FQDN - use ?fqdn=<fqdn>\n")
		return
	}

	fqdn := v[0]

	v = q["pass"]

	if len(v) == 0 || v[0] == "" {
		log.Error("No passphrase specified.")
		io.WriteString(resp, "no passphrase - use ?pass=<pass>\n")
		return
	}

	pass := v[0]

	client := gClients[fqdn]

	if client == nil || client.key != pass {
		log.Error("Invalid FQDN or passphrase")
		io.WriteString(resp, "invalid FQDN or passphrase\n")
		return
	}

	res := true

	log.Info(0, "Validated DNS update request: %s --> %s", fqdn, ip)

	if ip != client.ipv4 {
		log.Info(1, "Updating DNS entry: %s --> %s", fqdn, ip)
		script := createNsupdateScriptIpv4(fqdn, ip)

		if script != "" {
			if runNsupdate(script) {
				log.Info(0, "Updated DNS entry: %s --> %s", fqdn, ip)
				client.ipv4 = ip
			} else {
				res = false
			}
		} else {
			res = false
		}

		os.Remove(script)
	}

	if res {
		io.WriteString(resp, "ok\n")
	} else {
		io.WriteString(resp, "fail\n")
	}
}

func retrieveRemoteIp(req *http.Request) string {
	q := req.URL.Query()

	v := q["ipv4"]

	if len(v) > 0 {
		ip := v[0]
		if ip != "" {
			return ip
		}
	}

	v = req.Header["X-Real-Ip"]

	if len(v) > 0 {
		return v[0]
	}

	return ""
}

func main() {
	prgName := os.Args[0]
	log.SetVerbosity(0)

	if len(os.Args) != 2 {
		log.Fatal("Usage: %s <config file>", prgName)
	}

    cfgFile := os.Args[1]

    if !readConfig(cfgFile) {
    	log.Fatal("Failed to read configuratonfile: %s", cfgFile)
	}

	initClients()

	if len(gClients) > 0 {
		serverUrl()
	}

	if !client() {
		log.Error("DDNS update failed.")
		os.Exit(1)
	}

	os.Exit(0)
}
