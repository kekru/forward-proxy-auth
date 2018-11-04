package authenticator

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"github.com/kekru/forward-proxy-auth/model"
	log "github.com/sirupsen/logrus"
	"gopkg.in/ldap.v2"
)

type LdapAuth struct {
	LdapURL        string
	BaseDN         string
	BindDN         string
	BindDNPassword string
	UserFilter     string
	GroupFilter    string

	UserNameField           string
	UserEmailField          string
	UserFieldForGroupFilter string
	GroupNameField          string

	connection *ldap.Conn
}

func (ldapAuth *LdapAuth) Authenticate(username string, password string) (user *model.User, err error) {

	if ldapAuth.isEmpty(ldapAuth.BindDN) || ldapAuth.isEmpty(ldapAuth.BindDNPassword) ||
		ldapAuth.isEmpty(username) || ldapAuth.isEmpty(password) {
		return nil, errors.New("BindDN, BindPassword, username or passwort not set")
	}

	username = ldap.EscapeFilter(username)

	ldapURLParts := strings.Split(ldapAuth.LdapURL, "://")
	scheme, hostAndPort := strings.ToLower(ldapURLParts[0]), ldapURLParts[1]
	host := hostAndPort[:strings.Index(hostAndPort, ":")]

	defer ldapAuth.close()

	switch scheme {
	case "ldap":
		ldapAuth.connection, err = ldap.Dial("tcp", hostAndPort)

	case "ldaps":
		ldapAuth.connection, err = ldap.DialTLS("tcp", hostAndPort, &tls.Config{ServerName: host})
	}

	if err != nil {
		return nil, err
	}

	err = ldapAuth.connection.Bind(ldapAuth.BindDN, ldapAuth.BindDNPassword)
	if err != nil {
		return nil, err
	}
	attributes := []string{ldapAuth.UserNameField, ldapAuth.UserEmailField, "cn", "dn"}
	userFilter := fmt.Sprintf(ldapAuth.UserFilter, username)

	searchRequest := ldap.NewSearchRequest(
		ldapAuth.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		userFilter,
		attributes,
		nil,
	)

	searchResult, err := ldapAuth.connection.Search(searchRequest)
	if err != nil {
		log.Debugf("Error getting user %s with filter %s, %s", username, userFilter, err)
		return nil, err
	}

	if len(searchResult.Entries) < 1 {
		return nil, errors.New(fmt.Sprintf("User not found with username: %s, filter: %s", username, userFilter))
	}

	if len(searchResult.Entries) > 1 {
		return nil, errors.New(fmt.Sprintf("Multiple results found for username: %s, filter: %s, number of results: %s", username, userFilter, len(searchResult.Entries)))
	}

	entry := searchResult.Entries[0]
	userDN := entry.DN

	user = &model.User{
		Name:  entry.GetAttributeValue(ldapAuth.UserNameField),
		Email: entry.GetAttributeValue(ldapAuth.UserEmailField),
	}

	usernameForGroupFilter := entry.GetAttributeValue(ldapAuth.UserFieldForGroupFilter)
	groupFilter := fmt.Sprintf(ldapAuth.GroupFilter, usernameForGroupFilter)

	searchRequest = ldap.NewSearchRequest(
		ldapAuth.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		groupFilter,
		[]string{ldapAuth.GroupNameField},
		nil,
	)
	searchResult, err = ldapAuth.connection.Search(searchRequest)
	if err != nil {
		log.Debugf("Error getting groups for user %s identified in goups by %s, %s", username, groupFilter, err)
		return nil, err
	}

	for _, groupEntry := range searchResult.Entries {
		groupName := groupEntry.GetAttributeValue(ldapAuth.GroupNameField)
		user.Groups = append(user.Groups, groupName)
	}

	log.Debugf("Read User from LDAP: %s", user)

	err = ldapAuth.connection.Bind(userDN, password)
	if err != nil {
		log.Debugf("Authentication failed for username %s: %s", username, err)
		return nil, err
	}

	return
}

func (ldapAuth *LdapAuth) isEmpty(value string) bool {
	return len(strings.TrimSpace(value)) == 0
}

func (ldapAuth *LdapAuth) close() {
	if ldapAuth.connection != nil {
		ldapAuth.connection.Close()
		ldapAuth.connection = nil
	}
}
