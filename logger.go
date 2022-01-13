package main

import (
	"bytes"
	"github.com/felixge/httpsnoop"
	log "github.com/sirupsen/logrus"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//https://husobee.github.io/golang/ip-address/2015/12/17/remote-ip-go.html
//ipRange - a structure that holds the start and end of a range of ip addresses
type ipRange struct {
	start net.IP
	end   net.IP
}

// inRange - check to see if a given ip address is within a range given
func inRange(r ipRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}
	return false
}

var privateRanges = []ipRange{
	{start: net.ParseIP("10.0.0.0"),
		end: net.ParseIP("10.255.255.255")},
	{start: net.ParseIP("100.64.0.0"),
		end: net.ParseIP("100.127.255.255")},
	{start: net.ParseIP("172.16.0.0"),
		end: net.ParseIP("172.31.255.255")},
	{start: net.ParseIP("192.0.0.0"),
		end: net.ParseIP("192.0.0.255")},
	{start: net.ParseIP("192.168.0.0"),
		end: net.ParseIP("192.168.255.255")},
	{start: net.ParseIP("198.18.0.0"),
		end: net.ParseIP("198.19.255.255")},
}

// LogReqInfo describes info about HTTP request
type HTTPReqInfo struct {
	// GET etc.
	method  string
	uri     string
	referer string
	ipaddr  string
	// response code, like 200, 404
	code int
	// number of bytes of the response sent
	size int64
	// how long did it take to
	duration  time.Duration
	userAgent string
}

//https://presstige.io/p/Logging-HTTP-requests-in-Go-233de7fe59a747078b35b82a1b035d36
func logRequestHandler(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ri := &HTTPReqInfo{
			method:    r.Method,
			uri:       r.URL.String(),
			referer:   r.Header.Get("Referer"),
			userAgent: r.Header.Get("User-Agent"),
		}

		ri.ipaddr = getIPAdress(r)

		// this runs handler h and captures information about
		// HTTP request
		m := httpsnoop.CaptureMetrics(h, w, r)

		ri.code = m.Code
		ri.size = m.Written
		ri.duration = m.Duration
		logHTTPReq(ri, w.Header())
	}
	return http.HandlerFunc(fn)
}

func getIPAdress(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left until we get a public address
		// that will be the address right before our proxy.
		for i := len(addresses) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])
			// header can contain spaces too, strip those out.
			realIP := net.ParseIP(ip)
			if !realIP.IsGlobalUnicast() || isPrivateSubnet(realIP) {
				// bad address, go to next
				continue
			}
			return ip
		}
	}
	//Get IP from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "n/a"
	}
	return ip
}

func isPrivateSubnet(ipAddress net.IP) bool {
	// my use case is only concerned with ipv4 atm
	if ipCheck := ipAddress.To4(); ipCheck != nil {
		// iterate over all our ranges
		for _, r := range privateRanges {
			// check if this ip is in a private range
			if inRange(r, ipAddress) {
				return true
			}
		}
	}
	return false
}

func logHTTPReq(ri *HTTPReqInfo, h http.Header) {
	referer := strings.Replace(ri.referer, `"`, `""`, -1)
	if referer == "" {
		referer = "-"
	}
	uri := strings.Replace(ri.uri, `"`, `""`, -1)
	userAgent := strings.Replace(ri.userAgent, `"`, `""`, -1)

	msg := `[` +
		strconv.Itoa(ri.code) + `],` +
		ri.ipaddr + `,` +
		strconv.Itoa(int(ri.duration.Milliseconds())) + `ms,` +
		ri.method + `,"` +
		uri + `",` +
		strconv.FormatInt(ri.size, 10) + `,"` +
		referer + `","` +
		userAgent + `"`

	if ri.code == 302 || ri.code == 303 {
		msg += `,loc:` +
			h.Get("Location")
	}

	if ri.code >= 400 {
		log.Error(msg)
	} else {
		log.Print(msg)
	}
}
