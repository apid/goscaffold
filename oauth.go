package goscaffold

import (
	"context"
	"encoding/json"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
	"net/http"
)

const params = "params"

/* Errors to return */
type Errors []string

/*
The SSO key parameters
*/
type ssoKey struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
	Kty   string `json:"kty"`
	Use   string `json:"use"`
	N     string `json:"n"`
	E     string `json:"e"`
}

/*
OAuth structure that provides http connection to the URL that has the public
key for verifying the JWT token
*/
type OAuth struct {
	keyURL string
	client *http.Client
}

/*
The interface functions offered to clients that act on OAuth param,
used to verify JWT tokens for the Http handler functions client
wishes to validate against (via SSOHandler).
*/
type OAuthService interface {
	SSOHandler(p string, h func(http.ResponseWriter, *http.Request)) (string, httprouter.Handle)
}

/*
SetParamsInRequest Sets the params and its values in the request
*/
func SetParamsInRequest(r *http.Request, ps httprouter.Params) *http.Request {
	newContext := context.WithValue(r.Context(), params, ps)
	return r.WithContext(newContext)
}

/*
FetchParams fetches the param values, given the params in the request
*/
func FetchParams(r *http.Request) httprouter.Params {
	ctx := r.Context()
	return ctx.Value(params).(httprouter.Params)
}

/*
SSOHandler offers the users the flexibility of choosing which http handlers
need JWT validation.
*/
func (a *OAuth) SSOHandler(p string, h func(http.ResponseWriter, *http.Request)) (string, httprouter.Handle) {
	return p, a.VerifyOAuth(alice.New().ThenFunc(h))
}

/*
VerifyOAuth verifies the JWT token in the request using the public key configured
via CreateOAuth constructor.
*/
func (a *OAuth) VerifyOAuth(next http.Handler) httprouter.Handle {

	return func(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) {

		jwt, err := jws.ParseJWTFromRequest(r)
		if err != nil {
			WriteErrorResponse(http.StatusBadRequest, err.Error(), rw)
			return
		}

		/* Validate the JWT */
		err = a.Validate(jwt)
		if err != nil {
			WriteErrorResponse(http.StatusBadRequest, err.Error(), rw)
			return
		}

		/* Set the params in the request */
		r = SetParamsInRequest(r, ps)
		next.ServeHTTP(rw, r)
	}

}

/*
ValidateKey validate the jwt and return an error if it fails
*/
func (a *OAuth) Validate(jwt jwt.JWT) error {

	r, err := a.client.Get(a.keyURL)

	if err != nil {
		return err
	}

	defer r.Body.Close()
	ssoKey := &ssoKey{}
	err = json.NewDecoder(r.Body).Decode(ssoKey)
	if err != nil {
		return err
	}

	/* Retrieve the Public Key */
	publieKey, err := crypto.ParseRSAPublicKeyFromPEM([]byte(ssoKey.Value))
	if err != nil {
		return err
	}

	/* Return the status of validation */
	return jwt.Validate(publieKey, crypto.SigningMethodRS256)
}

/*
WriteErrorResponse write a non 200 error response
*/
func WriteErrorResponse(statusCode int, message string, w http.ResponseWriter) {
	errors := Errors{message}
	WriteErrorResponses(statusCode, errors, w)
}

/*
WriteErrorResponses write our error responses
*/
func WriteErrorResponses(statusCode int, errors Errors, w http.ResponseWriter) {
	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(errors)
}
