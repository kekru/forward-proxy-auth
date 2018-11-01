package authenticator

import (
	"github.com/kekru/forward-proxy-auth/model"

	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/jtblin/go-ldap-client"
)

type LdapAuth struct {
	Client                *ldap.LDAPClient
	UserNameField         string
	UserEmailField        string
	UserNameInGroupsField string
}

func (ldapAuth *LdapAuth) Authenticate(username string, password string) (user *model.User, err error) {

	defer ldapAuth.Client.Close()

	ok, userLdap, err := ldapAuth.Client.Authenticate(username, password)
	if err != nil {
		log.Debugf("Error authenticating user %s: %s", username, err)
		return nil, err
	}
	if !ok {
		return nil, errors.New("Authenticating failed for user " + username)
	}
	log.Debugf("Found LDAP user: %s", userLdap)

	usernameInGroups := userLdap[ldapAuth.UserNameInGroupsField]
	groups, err := ldapAuth.Client.GetGroupsOfUser(usernameInGroups)
	if err != nil {
		log.Debugf("Error getting groups for user %s identified in goups by %s, %s", username, usernameInGroups, err)
		return nil, err
	}
	log.Debugf("User %s has the ldap groups %s", username, groups)

	user = &model.User{
		Name:   userLdap[ldapAuth.UserNameField],
		Email:  userLdap[ldapAuth.UserEmailField],
		Groups: groups,
	}
	return
}
