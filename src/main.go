package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"log"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	post "github.com/SND1231/portfolio_gateway/proto/post"
	user "github.com/SND1231/portfolio_gateway/proto/user"
)

func ClientIAuthnterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req interface{},
		reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {

		md, _ := metadata.FromOutgoingContext(ctx)

		authorization := ""
		if len(md["authorization"]) != 0 {
			authorization = md["authorization"][0]
		}
		if !CheckAuthorization(method, authorization) {
			return status.New(codes.Unauthenticated, "トークンが設定されていません").Err()
		}
		err := invoker(ctx, method, req, reply, cc, opts...)
		return err
	}
}

func CheckAuthorization(method string, authorization string) bool {
	switch method {
	case "/user.UserService/Login":
		return true
	case "/user.UserService/CreateUser":
		return true
	case "/post.PostService/GetPosts":
		return true
	default:
		return AuthToken(authorization)
	}
}

func AuthToken(authorization string) bool {
	if authorization == "" {
		return false
	}

	token, err := jwt.Parse(authorization, func(token *jwt.Token) (interface{}, error) {
		//このようなアルゴリズムチェックを入れている記事が多い。
		//HMAC(共通),ECDSA,RSA(公開)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("alg error")
		}
		//keyを返す
		return []byte("secret"), nil
	})

	if err != nil {
		log.Fatal(err)
		return false
	}

	if !token.Valid {
		log.Fatal("valid error")
		return false
	}

	return true
}

func CustomHTTPError(ctx context.Context, _ *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, _ *http.Request, err error) {
	const fallback = `{"error": "failed to marshal error message"}`

	w.Header().Set("Content-type", marshaler.ContentType())
	w.WriteHeader(runtime.HTTPStatusFromCode(grpc.Code(err)))

	st, _ := status.FromError(err)
	var detail_list []map[string]interface{}
	for _, detail := range st.Details() {
		switch t := detail.(type) {
		case *errdetails.BadRequest:
			for _, violation := range t.GetFieldViolations() {
				detail_list = append(detail_list,
					map[string]interface{}{"feild": violation.GetField(), "description": violation.GetDescription()})
			}
		}
	}

	err_body := map[string]interface{}{"error": grpc.ErrorDesc(err), "details": detail_list}
	jErr := json.NewEncoder(w).Encode(err_body)

	if jErr != nil {
		w.Write([]byte(fallback))
	}
}

func main() {
	runtime.HTTPError = CustomHTTPError

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux()

	opts := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithUnaryInterceptor(ClientIAuthnterceptor()),
	}
	// gRPCのUserServiceにアクセスするための定義を追加
	err := user.RegisterUserServiceHandlerFromEndpoint(ctx, mux, "user:9001", opts)
	if err != nil {
		log.Fatal(err)
	}

	err = post.RegisterPostServiceHandlerFromEndpoint(ctx, mux, "post:9002", opts)
	if err != nil {
		log.Fatal(err)
	}

	handler := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{http.MethodPost, http.MethodGet, http.MethodPut, http.MethodDelete}),
		handlers.AllowedHeaders([]string{"Authorization", "Content-Type", "Accept-Encoding", "Accept"}),
	)(mux)

	err = http.ListenAndServe(":8081", handler)
	if err != nil {
		log.Fatal(err)
	}
}
