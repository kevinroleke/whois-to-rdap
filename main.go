package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ryanmab/rdap-go/pkg/client"
	"github.com/ryanmab/rdap-go/pkg/client/response/dns"
)

const (
	MAX_CONN_TIME = 10 * time.Second
	MAX_REQ_LENGTH = 64
	ERROR = `
@
@ whois-to-rdap proxy server
@ There was a critical error
@
`
	HELP = `
@
@ whois-to-rdap proxy server
@ Please see https://github.com/kevinroleke/whois-to-rdap for more information
@
`
	NO_MATCH = HELP + `
No match for "%s".`
)

// https://gist.github.com/chmike/d4126a3247a6d9a70922fc0e8b4f4013
func checkDomain(name string) error {
	switch {
	case len(name) == 0:
		return nil // an empty domain name will result in a cookie without a domain restriction
	case len(name) > 255:
		return fmt.Errorf("domain name length is %d, can't exceed 255", len(name))
	}
	var l int
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '.' {
			// check domain labels validity
			switch {
			case i == l:
				return fmt.Errorf("domain has invalid character '.' at offset %d, label can't begin with a period", i)
			case i-l > 63:
				return fmt.Errorf("domain byte length of label '%s' is %d, can't exceed 63", name[l:i], i-l)
			case name[l] == '-':
				return fmt.Errorf("domain label '%s' at offset %d begins with a hyphen", name[l:i], l)
			case name[i-1] == '-':
				return fmt.Errorf("domain label '%s' at offset %d ends with a hyphen", name[l:i], l)
			}
			l = i + 1
			continue
		}
		// test label character validity, note: tests are ordered by decreasing validity frequency
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b >= 'A' && b <= 'Z') {
			// show the printable unicode character starting at byte offset i
			c, _ := utf8.DecodeRuneInString(name[i:])
			if c == utf8.RuneError {
				return fmt.Errorf("domain has invalid rune at offset %d", i)
			}
			return fmt.Errorf("domain has invalid character '%c' at offset %d", c, i)
		}
	}
	// check top level domain validity
	switch {
	case l == len(name):
		return fmt.Errorf("domain has missing top level domain, domain can't end with a period")
	case len(name)-l > 63:
		return fmt.Errorf("domain's top level domain '%s' has byte length %d, can't exceed 63", name[l:], len(name)-l)
	case name[l] == '-':
		return fmt.Errorf("domain's top level domain '%s' at offset %d begin with a hyphen", name[l:], l)
	case name[len(name)-1] == '-':
		return fmt.Errorf("domain's top level domain '%s' at offset %d ends with a hyphen", name[l:], l)
	case name[l] >= '0' && name[l] <= '9':
		return fmt.Errorf("domain's top level domain '%s' at offset %d begins with a digit", name[l:], l)
	}
	return nil
}

func handleSuccess(req string, conn net.Conn) {
	res, err := rdapQuery(req)
	if err != nil {
		fmt.Fprintf(conn, NO_MATCH + "\n\nEither we don't have the RDAP server for that TLD, or the domain does not exist.", req)
		conn.Close()
		return
	}
	j, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		conn.Write([]byte(ERROR))
		conn.Close()
		return
	}

	conn.Write(append([]byte(HELP), j...))
	conn.Close()
}

func handleClient(conn net.Conn) {
	conn.SetReadDeadline(time.Now().Add(MAX_CONN_TIME))
	request := make([]byte, MAX_REQ_LENGTH)
	defer conn.Close()

	for {
		readLen, err := conn.Read(request)

		if err != nil {
			log.Println(err)
			break
		}

		if readLen == 0 {
			break
		} else {
			req := strings.TrimSpace(string(request[:readLen]))

			if req == "help" {
				conn.Write([]byte(HELP))
				conn.Close()
			} else {
				if err := checkDomain(req); err != nil {
					fmt.Fprintf(conn, NO_MATCH + "\n\nInvalid domain: %s", req, err.Error())
					conn.Close()
				} else {
					handleSuccess(req, conn)
				}
			}
			break
		}
	}
}

func listen(port string) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", port)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()

		if err != nil {
			continue
		}

		go handleClient(conn)
	}
}

func rdapQuery(domain string) (*dns.Response, error) {
	client := client.New()

	return client.LookupDomain(domain)
}

func main() {
	log.Fatal(listen(":4343"))
}
