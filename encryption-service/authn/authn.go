// Copyright 2020 CYBERCRYPT
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package authn

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/gofrs/uuid"
	"google.golang.org/protobuf/proto"

	"encryption-service/crypt"
)

// Authenticator represents a MessageAuthenticator used for creating and logging in users
type Authenticator struct {
	MessageAuthenticator *crypt.MessageAuthenticator
}

type AuthenticatorInterface interface {
	SerializeAccessToken(accessToken *AccessToken, nonce []byte) (string, error)
	ParseAccessToken(token string) (*AccessToken, error)
}

// ScopeType represents the different scopes a user could be granted
type ScopeType uint64

const ScopeNone ScopeType = 0
const (
	ScopeRead ScopeType = 1 << iota
	ScopeCreate
	ScopeIndex
	ScopeObjectPermissions
	ScopeUserManagement
	ScopeEnd
)

func (us ScopeType) IsValid() error {
	if us < ScopeEnd {
		return nil
	}
	return errors.New("invalid combination of scopes")
}

func (us ScopeType) HasScopes(tar ScopeType) bool {
	return (us & tar) == tar
}

type AccessToken struct {
	UserID uuid.UUID
	// this field is not exported to prevent other parts
	// of the encryption server to depend on its implementation
	userScopes ScopeType
}

func (a *AccessToken) New(userID uuid.UUID, userScopes ScopeType) error {
	if userID.Version() != 4 || userID.Variant() != uuid.VariantRFC4122 {
		return errors.New("invalid user ID UUID version or variant")
	}

	if userScopes >= ScopeEnd {
		return errors.New("invalid scope")
	}

	a.UserID = userID
	a.userScopes = userScopes
	return nil
}

func (a *AccessToken) HasScopes(scopes ScopeType) bool {
	return a.userScopes.HasScopes(scopes)
}

func (a *Authenticator) SerializeAccessToken(accessToken *AccessToken, nonce []byte) (string, error) {
	if len(nonce) != 16 {
		return "", errors.New("Invalid nonce length")
	}

	if accessToken.userScopes.IsValid() != nil {
		return "", errors.New("Invalid scopes")
	}

	if accessToken.UserID.Version() != 4 || accessToken.UserID.Variant() != uuid.VariantRFC4122 {
		return "", errors.New("Invalid userID UUID")
	}

	userScope := []AccessTokenClient_UserScope{}
	for i := ScopeType(1); i < ScopeEnd; i <<= 1 {
		if (accessToken.userScopes & i) == 0 {
			continue
		}
		switch i {
		case ScopeRead:
			userScope = append(userScope, AccessTokenClient_READ)
		case ScopeCreate:
			userScope = append(userScope, AccessTokenClient_CREATE)
		case ScopeIndex:
			userScope = append(userScope, AccessTokenClient_INDEX)
		case ScopeObjectPermissions:
			userScope = append(userScope, AccessTokenClient_OBJECTPERMISSIONS)
		case ScopeUserManagement:
			userScope = append(userScope, AccessTokenClient_USERMANAGEMENT)
		default:
			return "", errors.New("Invalid scopes")
		}
	}

	accessTokenClient := &AccessTokenClient{
		UserId:     accessToken.UserID.Bytes(),
		UserScopes: userScope,
	}

	data, err := proto.Marshal(accessTokenClient)
	if err != nil {
		return "", err
	}

	msg := append(nonce, data...)
	tag, err := a.MessageAuthenticator.Tag(crypt.TokenDomain, msg)
	if err != nil {
		return "", err
	}

	nonceStr := base64.RawURLEncoding.EncodeToString(nonce)
	dataStr := base64.RawURLEncoding.EncodeToString(data)
	tagStr := base64.RawURLEncoding.EncodeToString(tag)

	return dataStr + "." + nonceStr + "." + tagStr, nil
}

func (a *Authenticator) ParseAccessToken(token string) (*AccessToken, error) {
	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		return nil, errors.New("invalid token format")
	}

	data, err := base64.RawURLEncoding.DecodeString(tokenParts[0])
	if err != nil {
		return nil, errors.New("invalid data portion of token")
	}

	nonce, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, errors.New("invalid nonce portion of token")
	}

	tag, err := base64.RawURLEncoding.DecodeString(tokenParts[2])
	if err != nil {
		return nil, errors.New("invalid tag portion of token")
	}

	msg := append(nonce, data...)
	valid, err := a.MessageAuthenticator.Verify(crypt.TokenDomain, msg, tag)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("invalid token")
	}

	accessTokenClient := &AccessTokenClient{}
	err = proto.Unmarshal(data, accessTokenClient)
	if err != nil {
		return nil, err
	}

	uuid, err := uuid.FromBytes(accessTokenClient.UserId)
	if err != nil {
		return nil, err
	}

	var userScopes ScopeType
	for _, scope := range accessTokenClient.UserScopes {
		switch scope {
		case AccessTokenClient_READ:
			userScopes |= ScopeRead
		case AccessTokenClient_CREATE:
			userScopes |= ScopeCreate
		case AccessTokenClient_INDEX:
			userScopes |= ScopeIndex
		case AccessTokenClient_OBJECTPERMISSIONS:
			userScopes |= ScopeObjectPermissions
		case AccessTokenClient_USERMANAGEMENT:
			userScopes |= ScopeUserManagement
		default:
			return nil, errors.New("Invalid Scopes in Token")
		}
	}
	return &AccessToken{
		UserID:     uuid,
		userScopes: userScopes,
	}, nil
}
