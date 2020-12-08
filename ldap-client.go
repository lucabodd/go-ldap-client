// Package ldap provides a simple ldap client to authenticate,
// retrieve basic information and groups for a user.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"gopkg.in/ldap.v3"
)

type LDAPClient struct {
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	PolicyBase		   string
	GroupFilter        string // e.g. "(memberUid=%s)"
	Host               string
	ServerName         string
	UserFilter         string // e.g. "(uid=%s)"
	Conn               *ldap.Conn
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
	ClientCertificates []tls.Certificate // Adding client certificates
}

// Connect connects to the ldap backend.
func (lc *LDAPClient) Connect() error {
	if lc.Conn == nil {
		var l *ldap.Conn
		var err error
		address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
		if !lc.UseSSL {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				return err
			}

			// Reconnect with TLS
			if !lc.SkipTLS {
				err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
				if err != nil {
					return err
				}
			}
		} else {
			config := &tls.Config{
				InsecureSkipVerify: lc.InsecureSkipVerify,
				ServerName:         lc.ServerName,
			}
			if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
				config.Certificates = lc.ClientCertificates
			}
			l, err = ldap.DialTLS("tcp", address, config)
			if err != nil {
				return err
			}
		}

		lc.Conn = l
	}
	return nil
}

// Close closes the ldap backend connection.
func (lc *LDAPClient) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

// Authenticate authenticates the user against the ldap backend.
func (lc *LDAPClient) Authenticate(username, password string) (bool, map[string]string, error) {
	err := lc.Connect()
	if err != nil {
		return false, nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return false, nil, err
		}
	}

	attributes := append(lc.Attributes, "dn")
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return false, nil, err
	}

	if len(sr.Entries) < 1 {
		return false, nil, errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return false, nil, errors.New("Too many entries returned")
	}

	userDN := sr.Entries[0].DN
	user := map[string]string{}
	for _, attr := range lc.Attributes {
		user[attr] = sr.Entries[0].GetAttributeValue(attr)
	}

	// Bind as the user to verify their password
	err = lc.Conn.Bind(userDN, password)
	if err != nil {
		return false, user, err
	}

	// Rebind as the read only user for any further queries
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return true, user, err
		}
	}

	lc.Close()
	return true, user, nil
}

// GetGroupsOfUser returns the group for a user.
func (lc *LDAPClient) GetUserGroups(username string) ([]string, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.GroupFilter, username),
		[]string{"cn"}, // can it be something else than "cn"?
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	groups := []string{}
	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	lc.Close()
	return groups, nil
}

// GetUserAttribute returns user specified attribute.
func (lc *LDAPClient) GetUserAttribute(username string, attribute string) (string, error) {
	err := lc.Connect()
	if err != nil {
		return "", err
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		[]string{attribute},
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if(len(sr.Entries)==0){
		return "", errors.New("(go-ldap-client:GetUserAttribute) ->  attribute for user not found")
	}

	res := sr.Entries[0].GetAttributeValue(attribute);
	lc.Close()
	return res, nil
}

// GetUserAttribute returns user specified attribute.
func (lc *LDAPClient) GetPolicyAttribute(parameter string, attribute string) (string, error) {
	err := lc.Connect()
	if err != nil {
		return "", err
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(cn=%s)", parameter),
		[]string{attribute},
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return "", err
	}
	res := sr.Entries[0].GetAttributeValue(attribute);
	lc.Close()
	return res, nil
}

// SetUserAttribute returns true if modification has been made successfully
func (lc *LDAPClient) SetUserAttribute(username string, attribute string, newValue string) (string, error) {
	err := lc.Connect()
	if err != nil {
		return "", err
	}

	//modifications require authentication
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return "", err
		}
	} else {
		return "", errors.New("BindDn or BindPassword not defined in config file")
	}

	//get users dn
	attributes := append(lc.Attributes, "dn")
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) < 1 {
		return "", errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return "", errors.New("Too many entries returned")
	}
	userDN := sr.Entries[0].DN

	//modify user atteribute
	modify := ldap.NewModifyRequest(userDN, nil)
	modify.Replace(attribute, []string{newValue})

	err = lc.Conn.Modify(modify)
	if err != nil {
		    return "", err
	}
	lc.Close()
	return newValue, nil
}

func (lc *LDAPClient) AddUserAttribute(username string, attribute string, value string) (string, error) {
	err := lc.Connect()
	if err != nil {
		return "", err
	}

	//modifications require authentication
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return "", err
		}
	} else {
		return "", errors.New("BindDn or BindPassword not defined in config file")
	}

	//get users dn
	attributes := append(lc.Attributes, "dn")
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) < 1 {
		return "", errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return "", errors.New("Too many entries returned")
	}
	userDN := sr.Entries[0].DN

	//modify user atteribute
	modify := ldap.NewModifyRequest(userDN, nil)
	modify.Add(attribute, []string{value})

	err = lc.Conn.Modify(modify)
	if err != nil {
		    return "", err
	}
	lc.Close()
	return value, nil
}
