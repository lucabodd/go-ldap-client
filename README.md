# go-ldap-client

Fork of Simple ldap client to authenticate, performa basic operations on ldap servers.
Provide utilities in order to authenticate, get groups, get & set attributes, and add new attributes to the user schema.

# Usage
The only external dependency is [gopkg.in/ldap.v3](http://gopkg.in/ldap.v3).
For the usage you can refer to code below

```golang
package main

import (
	"log"

	"github.com/jtblin/go-ldap-client"
)

func main() {
	client := &ldap.LDAPClient{
		Base:         "dc=example,dc=com",
		Host:         "ldap.example.com",
		Port:         389,
		UseSSL:       false,
		BindDN:       "uid=readonlysuer,ou=People,dc=example,dc=com",
		BindPassword: "readonlypassword",
		UserFilter:   "(uid=%s)",
		GroupFilter: "(memberUid=%s)",
		Attributes:   []string{"givenName", "sn", "mail", "uid"},
	}
	// It is the responsibility of the caller to close the connection
	defer client.Close()

	ok, user, err := client.Authenticate("username", "password")
	check(err)
	if !ok {
		log.Fatalf("Authenticating failed for user %s", "username")
	}
	log.Printf("User: %+v", user)

	groups, err := client.GetUserGroups("username")
	check(err)
	log.Printf("User groups: %+v " groups)
	attr, err := GetUserAttribute("username", "sshPublicKey")
	check(err)
	log.Printf("User requested schema attribute: %+v " attr)
	_, err = ldap.SetUserAttribute("username", "sshPublicKey", "ssh-rsa 3qefbgnqn...etc...")
	check(err)
	format := "20060102150405Z"
	now := time.Now().Format(format)
	_, err = ldap.AddUserAttribute("username", "pwdAccountLockedTime", now)
	check(err)
}
func check(e error) {
	if e != nil {
		log.Fatal(e)
		panic(e)
	}
}
```

## SSL (ldaps)

If you use SSL, you will need to pass the server name for certificate verification
or skip domain name verification e.g.`client.ServerName = "ldap.example.com"`.

# Why?

There are already [tons](https://godoc.org/?q=ldap) of ldap libraries for `golang` but most of them
are just forks of another one, most of them are too low level or too limited (e.g. do not return errors
which make it hard to troubleshoot issues).
