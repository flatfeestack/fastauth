module fastauth

go 1.13

replace github.com/vjeantet/ldapserver => github.com/tbocek/ldapserver v1.0.2-0.20200928134514-0dca787dbfcb

require (
	github.com/dimiro1/banner v1.0.0
	github.com/go-ldap/ldap/v3 v3.2.3
	github.com/google/go-cmp v0.5.2 // indirect
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/schema v1.2.0
	github.com/kr/pretty v0.1.0 // indirect
	github.com/lib/pq v1.8.0
	github.com/lor00x/goldap v0.0.0-20180618054307-a546dffdd1a3
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/mattn/go-sqlite3 v2.0.3+incompatible
	github.com/stretchr/testify v1.6.1
	github.com/vjeantet/ldapserver v1.0.1
	github.com/xlzd/gotp v0.0.0-20181030022105-c8557ba2c119
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
	golang.org/x/sys v0.0.0-20200929083018-4d22bbb62b3c // indirect
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1
)
