// Copyright 2021 CYBERCRYPT
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
	context "context"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/contextkeys"
	log "encryption-service/logger"
	"encryption-service/scopes"
	"encryption-service/services/health"
)

const baseAppPath string = "/app.Encryptonize/"
const baseEncPath string = "/enc.Encryptonize/"
const baseAuthPath string = "/authn.Encryptonize/"

var methodScopeMap = map[string]scopes.ScopeType{
	baseAuthPath + "CreateUser":      scopes.ScopeUserManagement,
	baseEncPath + "GetPermissions":   scopes.ScopeIndex,
	baseEncPath + "AddPermission":    scopes.ScopeObjectPermissions,
	baseEncPath + "RemovePermission": scopes.ScopeObjectPermissions,
	baseEncPath + "Store":            scopes.ScopeCreate,
	baseEncPath + "Retrieve":         scopes.ScopeRead,
	baseAppPath + "Version":          scopes.ScopeNone,
}

// CheckAccessToken verifies the authenticity of a token and
// that the token contains the required scope for the requested API
// The Access Token contains uid, scopes, and a random value
// this token has to be integrity protected (e.g. by an HMAC)
func (au *Authn) CheckAccessToken(ctx context.Context) (context.Context, error) {
	// Grab method name
	methodName, ok := ctx.Value(contextkeys.MethodNameCtxKey).(string)
	if !ok {
		err := status.Errorf(codes.Internal, "AuthenticateUser: Internal error during authentication")
		log.Error(ctx, "Could not typecast methodName to string", err)
		return nil, err
	}

	// Don't authenticate health checks
	// IMPORTANT! This check MUST stay at the top of this function
	if methodName == health.HealthEndpointCheck || methodName == health.HealthEndpointWatch || methodName == health.ReflectionEndpoint {
		return ctx, nil
	}

	token, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		log.Error(ctx, "AuthenticateUser: Couldn't find token in metadata", err)
		return nil, status.Errorf(codes.InvalidArgument, "missing access token")
	}

	accessToken, err := au.UserAuthenticator.ParseAccessToken(token)
	if err != nil {
		log.Error(ctx, "AuthenticateUser: Unable to parse Access Token", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid access token")
	}

	newCtx := context.WithValue(ctx, contextkeys.UserIDCtxKey, accessToken.UserID())

	reqScope, ok := methodScopeMap[methodName]
	if !ok {
		err = status.Errorf(codes.InvalidArgument, "invalid endpoint")
		log.Error(newCtx, "AuthenticateUser: Invalid Endpoint", err)
		return nil, err
	}

	if !accessToken.HasScopes(reqScope) {
		err = status.Errorf(codes.PermissionDenied, "access not authorized")
		log.Error(newCtx, "AuthenticateUser: Unauthorized access", err)
		return nil, err
	}

	log.Info(newCtx, "AuthenticateUser: User authenticated")

	return newCtx, nil
}