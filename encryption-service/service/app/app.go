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

package app

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"encryption-service/service/authn"
	"encryption-service/service/enc"
	"encryption-service/service/health"
	log "encryption-service/logger"
)

type App struct {
	Config       *Config
	EncService   *enc.EncService
	AuthnService *authn.AuthnService
}

type Config struct {
	KEK               []byte
	ASK               []byte
	AuthStorageURL    string
	ObjectStorageURL  string
	ObjectStorageID   string
	ObjectStorageKey  string
	ObjectStorageCert []byte
}

const stopSign = `
            uuuuuuuuuuuuuuuuuuuu
          u* uuuuuuuuuuuuuuuuuu *u
        u* u$$$$$$$$$$$$$$$$$$$$u *u
      u* u$$$$$$$$$$$$$$$$$$$$$$$$u *u
    u* u$$$$$$$$$$$$$$$$$$$$$$$$$$$$u *u
  u* u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u *u
u* u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u *u
$ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $
$ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $
$ $$$* ... *$...  ...$* ... *$$$  ... *$$$ $
$ $$$u **$$$$$$$  $$$  $$$$$  $$  $$$  $$$ $
$ $$$$$$uu *$$$$  $$$  $$$$$  $$  *** u$$$ $
$ $$$**$$$  $$$$  $$$u *$$$* u$$  $$$$$$$$ $
$ $$$$....,$$$$$..$$$$$....,$$$$..$$$$$$$$ $
$ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $
*u *$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$* u*
  *u *$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$* u*
    *u *$$$$$$$$$$$$$$$$$$$$$$$$$$$$* u*
      *u *$$$$$$$$$$$$$$$$$$$$$$$$* u*
        *u *$$$$$$$$$$$$$$$$$$$$* u*
          *u ****************** u*
            ********************

          RUNNING IN INSECURE MODE`

func ParseConfig() (*Config, error) {
	config := &Config{}

	var KEKHex string
	var ASKHex string
	var ObjectStorageCertFromEnv string
	a := []struct {
		EnvName      string
		ConfigTarget *string
		Optional     bool
	}{
		{"KEK", &KEKHex, false},
		{"ASK", &ASKHex, false},
		{"AUTH_STORAGE_URL", &config.AuthStorageURL, false},
		{"OBJECT_STORAGE_URL", &config.ObjectStorageURL, false},
		{"OBJECT_STORAGE_ID", &config.ObjectStorageID, false},
		{"OBJECT_STORAGE_KEY", &config.ObjectStorageKey, false},
		{"OBJECT_STORAGE_CERT", &ObjectStorageCertFromEnv, false},
	}

	for _, c := range a {
		v, ok := os.LookupEnv(c.EnvName)
		if !c.Optional && !ok {
			return nil, errors.New(c.EnvName + " env missing")
		}
		*c.ConfigTarget = v
	}

	KEK, err := hex.DecodeString(KEKHex)
	if err != nil {
		return nil, errors.New("KEK env couldn't be parsed (decode hex)")
	}
	if len(KEK) != 32 {
		return nil, errors.New("KEK must be 32 bytes (64 hex digits) long")
	}
	config.KEK = KEK

	ASK, err := hex.DecodeString(ASKHex)
	if err != nil {
		return nil, errors.New("ASK env couldn't be parsed (decode hex)")
	}
	if len(ASK) != 32 {
		return nil, errors.New("ASK must be 32 bytes (64 hex digits) long")
	}
	config.ASK = ASK

	// Read object storage ID, key and certificate from file if env var not specified
	if config.ObjectStorageID == "" {
		objectStorageID, err := ioutil.ReadFile("data/object_storage_id")
		if err != nil {
			return nil, errors.New("could not read OBJECT_STORAGE_ID from file")
		}
		objectStorageKey, err := ioutil.ReadFile("data/object_storage_key")
		if err != nil {
			return nil, errors.New("could not read OBJECT_STORAGE_KEY from file")
		}
		config.ObjectStorageID = strings.TrimSpace(string(objectStorageID))
		config.ObjectStorageKey = strings.TrimSpace(string(objectStorageKey))
	}
	if ObjectStorageCertFromEnv == "" {
		objectStorageCert, err := ioutil.ReadFile("data/object_storage.crt")
		if err != nil {
			return nil, errors.New("could not read OBJECT_STORAGE_CERT from file")
		}
		config.ObjectStorageCert = objectStorageCert
	} else {
		config.ObjectStorageCert = []byte(ObjectStorageCertFromEnv)
	}

	CheckInsecure(config)

	return config, nil
}

// Prevents an accidental deployment with testing parameters
func CheckInsecure(config *Config) {
	ctx := context.TODO()

	if os.Getenv("ENCRYPTION_SERVICE_INSECURE") == "1" {
		for _, line := range strings.Split(stopSign, "\n") {
			log.Warn(ctx, line)
		}
	} else {
		if hex.EncodeToString(config.KEK) == "0000000000000000000000000000000000000000000000000000000000000000" {
			log.Fatal(ctx, "Test KEK used outside of INSECURE testing mode", errors.New(""))
		}
		if hex.EncodeToString(config.ASK) == "0000000000000000000000000000000000000000000000000000000000000001" {
			log.Fatal(ctx, "Test ASK used outside of INSECURE testing mode", errors.New(""))
		}
	}
}

func (app *App) initgRPC(port int) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		msg := fmt.Sprintf("Failed to listen on port: %s", fmt.Sprint(port))
		log.Fatal(context.TODO(), msg, err)
	}

	// make gprc_recovery log panics and return generic errors to the caller
	recoveryOpt := grpc_recovery.WithRecoveryHandlerContext(
		func(ctx context.Context, p interface{}) error {
			log.Error(ctx, "panic recovered", fmt.Errorf("panic: %v", p))
			return status.Errorf(codes.Internal, "internal error")
		},
	)

	unaryInterceptors := []grpc.UnaryServerInterceptor{
		grpc_recovery.UnaryServerInterceptor(recoveryOpt),
		log.UnaryRequestIDInterceptor(),
		log.UnaryMethodNameInterceptor(),
		log.UnaryLogInterceptor(),
	}

	streamInterceptors := []grpc.StreamServerInterceptor{
		grpc_recovery.StreamServerInterceptor(recoveryOpt),
		log.StreamRequestIDInterceptor(),
		log.StreamMethodNameInterceptor(),
		log.StreamLogInterceptor(),
	}

	unaryInterceptors = append(unaryInterceptors, app.EncService.AuthStorageUnaryServerInterceptor())
	streamInterceptors = append(streamInterceptors, app.EncService.AuthStorageStreamingInterceptor())

	unaryInterceptors = append(unaryInterceptors, grpc_auth.UnaryServerInterceptor(app.AuthnService.CheckAccessToken))
	streamInterceptors = append(streamInterceptors, grpc_auth.StreamServerInterceptor(app.AuthnService.CheckAccessToken))

	// Add middlewares to the grpc server:
	// The order is important: AuthenticateUser needs AuthStore and Authstore needs MethodName
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(65*1024*1024),
		grpc_middleware.WithUnaryServerChain(
			unaryInterceptors...,
		),
		grpc_middleware.WithStreamServerChain(
			streamInterceptors...,
		),
	)

	enc.RegisterEncryptonizeServer(grpcServer, app.EncService)
	authn.RegisterEncryptonizeServer(grpcServer, app.AuthnService)

	// Register health checker to grpc server
	healthService := health.NewHealthChecker()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthService)

	return grpcServer, lis
}

func (app *App) StartServer() {
	ctx := context.TODO()

	// execute cli commands
	if len(os.Args) > 1 && filepath.Base(os.Args[0]) != "encryption-service.test" {
		log.Info(ctx, "Running in cli mode")

		cmd := os.Args[1]
		switch cmd {
		case "create-admin":
			msg := fmt.Sprintf("AuthenticatorInterface is of dynamic type: %v", reflect.TypeOf(app.AuthnService))
			log.Info(ctx, msg)
			if err := app.AuthnService.CreateAdminCommand(); err != nil {
				log.Fatal(ctx, "CreateAdminCommand", err)
			}
		default:
			msg := fmt.Sprintf("Invalid command: %v", cmd)
			log.Fatal(ctx, msg, errors.New(""))
		}

		return
	}

	// Setup gRPC listener
	var port int = 9000
	grpcServer, lis := app.initgRPC(port)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			msg := fmt.Sprintf("Failed to serve gRPC server over port %d", port)
			log.Fatal(ctx, msg, err)
		}
	}()

	msg := fmt.Sprintf("Running gRPC API on port :%v", port)
	log.Info(ctx, msg)

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGTERM and SIGINT
	signal.Notify(c, syscall.SIGTERM)
	signal.Notify(c, syscall.SIGINT)

	log.Info(ctx, "Press CTRL + C to shutdown server")
	<-c
	log.Info(ctx, "Received shutdown signal")

	// Try to gracefully shutdown
	go func() {
		grpcServer.GracefulStop()
		close(c)
	}()

	// Wait 25 seconds, if server hasn't shut down gracefully, force it
	timeToForceShutdown := time.NewTimer(25 * time.Second)
	select {
	case <-timeToForceShutdown.C:
		log.Info(ctx, "Timeout exceeded, forcing shutdown")
		grpcServer.Stop()
	case <-c:
		// TODO should we not check if this is an repeated ctrl-c, or the channel closing?
		timeToForceShutdown.Stop()
	}

	log.Info(ctx, "Shutting down")
}
