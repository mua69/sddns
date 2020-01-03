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
	"io/ioutil"
	"net"
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

var g_config = Config{Port:3200, NsupdateTTL:300, NsupdateCmd:"/usr/bin/nsupdate", NsupdateServer:"localhost"}
var g_clients = make(map[string]*Client)

func readConfig(filename string) bool {
        data, err := ioutil.ReadFile(filename)

        if err != nil {
                fmt.Printf("Failed to open config file \"%s\": %s\n", filename, err.Error())
                return false
        }

        err = json.Unmarshal(data, &g_config)
        if err != nil {
                fmt.Printf("Syntax error in config file %s: %v\n", filename, err)
                return false
        }

        return true
}

func initClients() {
	for _, c := range g_config.Clients {
		log.Info(1, "Client: %s", c.Fqdn)
		client := new(Client)
		client.fqdn = c.Fqdn
		client.key = c.Key
		g_clients[c.Fqdn] = client
	}
}

func createChallenge() string {
	buf := make([]byte, 32)

	n, err := rand.Read(buf)

	if (err != nil) {
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

	script := fmt.Sprintf("server %s\n", g_config.NsupdateServer)
	script += fmt.Sprintf("del %s in a\n", fqdn)
	script += fmt.Sprintf("add %s %d in a %s\n", fqdn, g_config.NsupdateTTL, ipv4)
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
	cmd := exec.Command(g_config.NsupdateCmd, "-k", g_config.NsupdateKey, script)
	out, err := cmd.CombinedOutput()

	if err != nil {
		log.Error("Failed to run nsupdate: %s", err.Error())
		return false
	}

	log.Info(0, "nsupdate output: %s", string(out))

	return true
}

func server() {
	adr := fmt.Sprintf("%s:%d", g_config.Host, g_config.Port)

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

	client := g_clients[fqdn]

	if client == nil {
		log.Info(1,"server: client not found")
		return
	}

	challenge := createChallenge()

	_, err = w.WriteString(challenge + "\n")
	if ioerror(err) {
		return
	}
	w.Flush()

	expectedResponse := createResponse(challenge, client.key)

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

	log.Info(1, "Updating DNS entry: %s --> %s", fqdn, ipv4)
	script := createNsupdateScriptIpv4(fqdn, ipv4)

	if script == "" {
		return
	}

	if runNsupdate(script) {
		log.Info(0, "Updated DNS entry: %s --> %s", fqdn, ipv4)
	}

	os.Remove(script)
}

func client() bool {
	adr := fmt.Sprintf("%s:%d", g_config.Host, g_config.Port)

	conn, err := net.Dial("tcp", adr)

	if err != nil {
		log.Error("Cannot connect to: %s", adr)
		return false
	}

	defer conn.Close()

	conn.SetDeadline(time.Now().Add(20*time.Second))

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	_, err = w.WriteString(g_config.Fqdn + "\n")

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

	response := createResponse(challenge, g_config.Key)
	log.Info(1, "client: response: '%s'", response)
	_, err = w.WriteString(response + "\n")

	if ioerror(err) {
		return false
	}

	w.Flush()


	return true
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

	if len(g_clients) > 0 {
		server()
	}

	if !client() {
		log.Error("DDNS update failed.")
		os.Exit(1)
	}

	os.Exit(0)
}
