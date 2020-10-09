package main

import (
	"fmt"
	ldap_client "github.com/go-ldap/ldap/v3"
	"github.com/lor00x/goldap/message"
	ldap "github.com/vjeantet/ldapserver"
	"log"
	"strings"
)

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	cn := getAttrDN(string(r.Name()), "cn")

	_, retryPossible, err := checkEmailPassword(cn, string(r.AuthenticationSimple()))
	if err != nil {
		res := ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials)
		if options.DetailedError {
			if retryPossible {
				res.SetDiagnosticMessage(fmt.Sprintf("invalid credentials for %v, please retry", string(r.Name())))
			} else {
				res.SetDiagnosticMessage(fmt.Sprintf("invalid credentials for %v", string(r.Name())))
			}
		}
		w.Write(res)
		return
	}

	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

/*
 * Parses a distinguished name and returns the CN portion.
 * Given a non-conforming string (such as an already-extracted CN),
 * it will be returned as-is.
 */
//https://github.com/chrishoffman/vault
//https://github.com/chrishoffman/vault/blob/master/builtin/credential/ldap/backend.go
func getAttrDN(dn string, atyp string) string {
	log.Printf("parsing basedn %v", dn)
	parsedDN, err := ldap_client.ParseDN(dn)
	if err != nil || len(parsedDN.RDNs) == 0 {
		// It was already a CN, return as-is
		log.Printf("could not parse %v, %v", dn, err)
		return dn
	}

	for _, rdn := range parsedDN.RDNs {
		for _, rdnAttr := range rdn.Attributes {
			log.Printf("found attr %v", rdnAttr.Type)
			if rdnAttr.Type == atyp {
				return rdnAttr.Value
			}
		}
	}

	// Default, return self
	log.Printf("default attr %v", dn)
	return dn
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()

	log.Printf("Request BaseDn=%s, Request Filter=%s, Request FilterString=%s, Request Attributes=%s, Request TimeLimit=%d",
		r.BaseObject(), r.Filter(), r.FilterString(), r.Attributes(), r.TimeLimit().Int())

	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-m.Done:
		log.Print("Leaving handleSearch...")
		return
	default:
	}

	var cn string
	if strings.Index(string(r.BaseObject()), "cn") >= 0 {
		cn = getAttrDN(string(r.BaseObject()), "cn")
	} else if strings.Index(r.FilterString(), "cn") >= 0 {
		cn = getAttrDN(r.FilterString(), "cn")
	} else {
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	_, err := dbSelect(cn)
	if err != nil {
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultUnwillingToPerform)
		w.Write(res)
		return
	}

	var e message.SearchResultEntry
	if strings.Index(string(r.BaseObject()), "cn") >= 0 {
		e = ldap.NewSearchResultEntry(string(r.BaseObject()))
		w.Write(e)
	} else {
		e = ldap.NewSearchResultEntry("cn=" + cn + ", " + string(r.BaseObject()))
		w.Write(e)
	}
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
