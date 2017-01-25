package goscaffold

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
	"net/http"
	"sync"
	"time"
)

var (
	gPkey   *rsa.PublicKey = nil
	rwMutex sync.RWMutex
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
CreateOAuth is a constructor that creates OAuth for OAuthService
interface. OAuthService interface offers method:-
(1) SSOHandler(): Offers the user to attach http handler for JWT
verification.
*/
func (s *HTTPScaffold) CreateOAuth(keyURL string) OAuthService {

	pk, err := getPublicKey(keyURL)
	if err == nil {
		setPkSafe(pk)
	}
	/*
	 * Routine that will fetch & update the public keys in safe manner
	 */
	updatePublicKeysPeriodic(keyURL)

	return &OAuth{}

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

		/* Parse the JWT from the input request */
		jwt, err := jws.ParseJWTFromRequest(r)
		if err != nil {
			WriteErrorResponse(http.StatusBadRequest, err.Error(), rw)
			return
		}

		/* Get the pulic key from cache */
		pk := getPkSafe()
		if pk == nil {
			WriteErrorResponse(http.StatusBadRequest, "Public key not configured. Validation failed.", rw)
			return
		}

		/* Validate the token */
		err = jwt.Validate(pk, crypto.SigningMethodRS256)
		if err != nil {
			WriteErrorResponse(http.StatusBadRequest, err.Error(), rw)
			return
		}

		/* Set the input params in the request */
		r = SetParamsInRequest(r, ps)
		next.ServeHTTP(rw, r)
	}

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

/*
updatePulicKeysPeriodic updates the cache periodically (every hour)
*/
func updatePublicKeysPeriodic(keyURL string) {

	ticker := time.NewTicker(3600 * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				pk, err := getPublicKey(keyURL)
				if err == nil {
					setPkSafe(pk)
				}
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
}

/*
getPubicKey: Loads the Public key in to memory and returns it.
*/
func getPublicKey(keyURL string) (*rsa.PublicKey, error) {

	client := &http.Client{}

	/* Connect to the server to fetch Key details */
	r, err := client.Get(keyURL)
	if err != nil {
		return nil, err
	}

	defer r.Body.Close()

	/* Decode the SSO Key */
	ssoKey := &ssoKey{}
	err = json.NewDecoder(r.Body).Decode(ssoKey)
	if err != nil {
		return nil, err
	}

	/* Retrieve the Public Key from SSO Key */
	publicKey, err := crypto.ParseRSAPublicKeyFromPEM([]byte(ssoKey.Value))
	if err != nil {
		return nil, err
	}
	return publicKey, nil

}

/*
setPkSafe Safely stores the Public Key (via a Write Lock)
*/
func setPkSafe(pk *rsa.PublicKey) {
	rwMutex.Lock()
	gPkey = pk
	rwMutex.Unlock()
}

/*
getPkSafe returns the stored key (via a read lock)
*/
func getPkSafe() *rsa.PublicKey {
	rwMutex.RLock()
	pk := gPkey
	rwMutex.RUnlock()
	return pk
}
