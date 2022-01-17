package main

import (
	"fmt"
	ldap_client "github.com/go-ldap/ldap/v3"
	"github.com/lor00x/goldap/message"
	log "github.com/sirupsen/logrus"
	ldap "github.com/vjeantet/ldapserver"
	"strings"
)

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	cn := getAttrDN(string(r.Name()), "cn")

	_, errString, err := checkEmailPassword(cn, string(r.AuthenticationSimple()))
	if err != nil {
		res := ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials)
		if opts.DetailedError {
			res.SetDiagnosticMessage(fmt.Sprintf("invalid credentials for %v, %v", string(r.Name()), errString))
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
			if strings.ToLower(rdnAttr.Type) == strings.ToLower(atyp) {
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
		log.Errorf("no cn found in [%v]", r.BaseObject())
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	dbRes, err := findAuthByEmail(cn)
	if err != nil {
		log.Errorf("cannot find user? %v", err)
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultUnwillingToPerform)
		w.Write(res)
		return
	}

	e := ldap.NewSearchResultEntry("cn=" + cn + ", " + string(r.BaseObject()))
	if dbRes.metaSystem != nil {
		jsonMapSystem, err := toJsonMap(dbRes.metaSystem)
		if err != nil {
			log.Errorf("no json stored? %v", err)
			res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultUnwillingToPerform)
			w.Write(res)
			return
		}
		group := jsonMapSystem["ldap_group"]
		if group != nil {
			e.AddAttribute("cn", message.AttributeValue(group.(string)))
		}
	}
	w.Write(e)
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
