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
package logger

import (
	"context"
	"os"

	"github.com/gofrs/uuid"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/metadata"

	"encryption-service/contextkeys"
)

// Initializes the global logger for uniform and structured logging
func init() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.JSONFormatter{})
	if stderrInfo, err := os.Stderr.Stat(); err == nil {
		if (stderrInfo.Mode() & os.ModeCharDevice) != 0 {
			log.SetFormatter(&log.TextFormatter{})
		}
	}
}

// Extracts logging fields from context. Does not set a field if it is not present in the context.
func fieldsFromCtx(ctx context.Context) log.Fields {
	fields := make(log.Fields)

	userID := ctx.Value(contextkeys.UserIDCtxKey)
	if userID != nil {
		fields["userId"] = userID
	}

	method := ctx.Value(contextkeys.MethodNameCtxKey)
	if method != nil {
		fields["method"] = method
	}

	requestID := ctx.Value(contextkeys.RequestIDCtxKey)
	if requestID != nil {
		fields["requestId"] = requestID
	}

	status := ctx.Value(contextkeys.StatusCtxKey)
	if status != nil {
		fields["status"] = status
	}

	objectID := ctx.Value(contextkeys.ObjectIDCtxKey)
	if objectID != nil {
		fields["objectId"] = objectID
	}

	targetID := ctx.Value(contextkeys.TargetIDCtxKey)
	if targetID != nil {
		fields["targetId"] = targetID
	}

	remoteIP := ctx.Value(contextkeys.RemoteIPCtxKey)
	if remoteIP != nil {
		fields["remoteIP"] = remoteIP
	}

	return fields
}

// The following functions wrap the standard logging functions
// in order to provide structured logging for our service
func Error(ctx context.Context, msg string, err error) {
	fields := fieldsFromCtx(ctx)
	fields["error"] = err
	log.WithFields(fields).Error(msg)
}

func Fatal(ctx context.Context, msg string, err error) {
	fields := fieldsFromCtx(ctx)
	fields["error"] = err
	log.WithFields(fields).Fatal(msg)
}

func Warn(ctx context.Context, msg string) {
	fields := fieldsFromCtx(ctx)
	log.WithFields(fields).Warn(msg)
}

func Info(ctx context.Context, msg string) {
	fields := fieldsFromCtx(ctx)
	log.WithFields(fields).Info(msg)
}

func Debug(ctx context.Context, msg string) {
	fields := fieldsFromCtx(ctx)
	log.WithFields(fields).Debug(msg)
}

// Inject full method name into unary call
func UnaryMethodNameInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		newctx := context.WithValue(ctx, contextkeys.MethodNameCtxKey, info.FullMethod)
		return handler(newctx, req)
	}
}

// Inject full method name into stream call
func StreamMethodNameInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		newCtx := context.WithValue(stream.Context(), contextkeys.MethodNameCtxKey, info.FullMethod)
		wrapped := grpc_middleware.WrapServerStream(stream)
		wrapped.WrappedContext = newCtx
		err := handler(srv, wrapped)

		return err
	}
}

// UnaryRequestIDInterceptor injects a request-scoped requestID which is later
// propagated to subsequent calls for tracing purposes
func UnaryRequestIDInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		requestID, err := uuid.NewV4()
		if err != nil {
			log.Error(ctx, "UnaryRequestIDInterceptor: Failed to create requestID", err)
			return nil, status.Errorf(codes.Internal, "error encountered while creating request ID")
		}

		newCtx := context.WithValue(ctx, contextkeys.RequestIDCtxKey, requestID)

		return handler(newCtx, req)
	}
}

// StreamRequestIDInterceptor injects a request-scoped requestID which is later
// propagated to subsequent calls for tracing purposes
func StreamRequestIDInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		requestID, err := uuid.NewV4()

		if err != nil {
			log.Error(context.TODO(), "StreamRequestIDInterceptor: Failed to create requestID", err)
			return status.Errorf(codes.Internal, "error encountered while creating request ID")
		}
		newCtx := context.WithValue(stream.Context(), contextkeys.RequestIDCtxKey, requestID)
		wrapped := grpc_middleware.WrapServerStream(stream)
		wrapped.WrappedContext = newCtx
		err = handler(srv, wrapped)

		return err
	}
}

// UnaryIpInterceptor injects the IP address of the caller into the context
func UnaryIPInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, ok := metadata.FromIncomingContext(ctx)

		if !ok {
			return nil, status.Errorf(codes.DataLoss, "failed to get metadata")
		}

		remoteIP := md["X-Real-Ip"]
		
		newCtx := context.WithValue(ctx, contextkeys.RemoteIPCtxKey, remoteIP)

		return handler(newCtx, req)
	}
}

// StreamIPIntercepto the remote IP address into the context
// propagated to subsequent calls for tracing purposes
func StreamIPInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {

		md, ok := metadata.FromIncomingContext(stream.Context())

		if !ok {
			status.Errorf(codes.DataLoss, "failed to get metadata")
		}

		remoteIP := md["X-Real-Ip"]
		newCtx := context.WithValue(stream.Context(), contextkeys.RemoteIPCtxKey, remoteIP)
		
		wrapped := grpc_middleware.WrapServerStream(stream)
		wrapped.WrappedContext = newCtx
		err := handler(srv, wrapped)

		return err
	}
}

// Logging interceptor for unary calls
func UnaryLogInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		status := "started"
		ctx = context.WithValue(ctx, contextkeys.StatusCtxKey, status)
		Info(ctx, "Request start")

		res, err := handler(ctx, req)

		status = "success"
		if err != nil {
			status = "failure"
		}
		ctx = context.WithValue(ctx, contextkeys.StatusCtxKey, status)

		Info(ctx, "Request completed")
		return res, err
	}
}

// Logging interceptor for stream calls
func StreamLogInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		log.Infof("srv: %v, stream: %v, info: %v", srv, stream, info)

		var newCtx context.Context
		wrapped := grpc_middleware.WrapServerStream(stream)
		wrapped.WrappedContext = newCtx
		err := handler(srv, wrapped)

		return err
	}
}
