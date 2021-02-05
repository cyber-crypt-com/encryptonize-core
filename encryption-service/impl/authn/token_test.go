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
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gofrs/uuid"

	"encryption-service/impl/crypt"
	"encryption-service/scopes"
)

var (
	ASK, _    = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	userID    = uuid.Must(uuid.FromString("00000000-0000-4000-8000-000000000002"))
	nonce, _  = hex.DecodeString("00000000000000000000000000000002")
	userScope = scopes.ScopeUserManagement
	AT        = &AccessToken{
		userID:     userID,
		userScopes: userScope,
	}

	messageAuthenticator, _ = crypt.NewMessageAuthenticator(ASK, crypt.TokenDomain)

	expectedSerialized = "ChAAAAAAAABAAIAAAAAAAAACEgEE"
	expectedMessage, _ = base64.RawURLEncoding.DecodeString(expectedSerialized)
	expectedTag, _     = messageAuthenticator.Tag(append(nonce, expectedMessage...))
	expectedToken      = "ChAAAAAAAABAAIAAAAAAAAACEgEE.AAAAAAAAAAAAAAAAAAAAAg." + base64.RawURLEncoding.EncodeToString(expectedTag)
)

func failOnError(message string, err error, t *testing.T) {
	if err != nil {
		t.Fatalf(message+": %v", err)
	}
}

func failOnSuccess(message string, err error, t *testing.T) {
	if err == nil {
		t.Fatalf("Test expected to fail: %v", message)
	}
}

func TestSerialize(t *testing.T) {
	token, err := AT.SerializeAccessToken(messageAuthenticator)
	if err != nil {
		t.Fatalf("SerializeAccessToken errored: %v", err)
	}

	serialized := strings.Split(token, ".")[0]

	if serialized != expectedSerialized {
		t.Errorf("Message doesn't match:\n%v\n%v", expectedToken, token)
	}

	t.Logf("dev admin token: %v", expectedToken)
}

func TestSerializeParseIdentity(t *testing.T) {
	token, err := AT.SerializeAccessToken(messageAuthenticator)
	if err != nil {
		t.Fatalf("SerializeAccessToken errored: %v", err)
	}

	ua := UserAuthenticator{
		Authenticator: messageAuthenticator,
	}
	AT2, err := ua.ParseAccessToken(token)
	failOnError("Parsing serialized access token failed", err, t)
	if AT2.UserID() != AT.UserID() || AT2.UserScopes() != AT.UserScopes() {
		t.Errorf("Serialize parse identity violated")
	}
}

func TestSerializeBaduserScope(t *testing.T) {
	BadScopeAT := &AccessToken{
		userID:     userID,
		userScopes: scopes.ScopeType(0xff),
	}

	token, err := BadScopeAT.SerializeAccessToken(messageAuthenticator)
	if (err == nil && err.Error() != "Invalid scopes") || token != "" {
		t.Errorf("formatMessage should have errored")
	}
}

func TestSerializeBadUserID(t *testing.T) {
	BadUUIDAT := &AccessToken{
		userID:     uuid.Nil,
		userScopes: userScope,
	}

	token, err := BadUUIDAT.SerializeAccessToken(messageAuthenticator)
	if (err == nil && err.Error() != "Invalid userID UUID") || token != "" {
		t.Errorf("formatMessage should have errored")
	}
}

func TestParseAccessToken(t *testing.T) {
	ua := UserAuthenticator{
		Authenticator: messageAuthenticator,
	}
	AT, err := ua.ParseAccessToken(expectedToken)
	failOnError("ParseAccessToken did fail", err, t)

	if AT.UserID() != userID || AT.UserScopes() != userScope {
		t.Errorf("Parsed Access Token contained different data!")
	}
}

// the checks for the modified parts of the token is currently handled
// in auth_handlers_test (TestAuthMiddlewareSwappedTokenParts)

func TestVerifyModifiedASK(t *testing.T) {
	ma, err := crypt.NewMessageAuthenticator([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), crypt.TokenDomain)
	failOnError("NewMessageAuthenticator errored", err, t)

	ua := UserAuthenticator{
		Authenticator: ma,
	}
	_, err = ua.ParseAccessToken(expectedToken)
	failOnSuccess("ParseAccessToken should have failed with modified ASK", err, t)
	if err.Error() != "invalid token" {
		t.Errorf("ParseAccessToken failed with different error. Expected \"invalid token\" but go %v", err)
	}
}

func TestSerializeAccessTokenAnyScopes(t *testing.T) {
	// try to create a use for every valid combination of scopes
	// even the empty set
	for i := uint64(0); i < uint64(scopes.ScopeEnd); i++ {
		uScope := scopes.ScopeType(i)
		tAT := &AccessToken{
			userID:     userID,
			userScopes: uScope,
		}
		_, err := tAT.SerializeAccessToken(messageAuthenticator)
		if err != nil {
			t.Fatalf("Failed to create/update user with scopes %v: %v", uScope, err)
		}
	}
}