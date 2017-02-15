package goscaffold

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
)

const params = "params"

// Errors to return
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
oauth provides http an connection to the URL that has the public
key for verifying the JWT token
*/
type oauth struct {
	gPkey   *rsa.PublicKey
	rwMutex *sync.RWMutex
}

/*
OAuthService offers interface functions that act on OAuth param,
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
	pk, _ := getPublicKey(keyURL)
	oa := &oauth{
		rwMutex: &sync.RWMutex{},
	}
	oa.setPkSafe(pk)
	oa.updatePublicKeysPeriodic(keyURL)
	return oa
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
func (a *oauth) SSOHandler(p string, h func(http.ResponseWriter, *http.Request)) (string, httprouter.Handle) {
	return p, a.VerifyOAuth(alice.New().ThenFunc(h))
}

/*
VerifyOAuth verifies the JWT token in the request using the public key configured
via CreateOAuth constructor.
*/
func (a *oauth) VerifyOAuth(next http.Handler) httprouter.Handle {

	return func(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) {

		var err2 error = nil

		/* Set the input params in the request if valid */
		r = SetParamsInRequest(r, ps)
		/* Set Default as OK */
		WriteStatusResponse(http.StatusOK, "", r)

		/* Parse the JWT from the input request */
		jwt, err1 := jws.ParseJWTFromRequest(r)
		if err1 != nil {
			WriteStatusResponse(http.StatusBadRequest, err1.Error(), r)
		}

		/* Get the pulic key from cache */
		if err1 == nil {
			pk := a.getPkSafe()
			if pk == nil {
				WriteStatusResponse(http.StatusBadRequest,
					"Public key not configured. Validation failed.", r)
			} else {
				err2 = jwt.Validate(pk, crypto.SigningMethodRS256)
				if err2 != nil {
					WriteStatusResponse(http.StatusBadRequest,
						err2.Error(), r)
				}
			}
		}
		next.ServeHTTP(rw, r)
	}
}

/*
WriteStatusResponse updates the validation outcome in the header.
*/
func WriteStatusResponse(statusCode int, message string, r *http.Request) {
	r.Header.Set("StatusCode", strconv.Itoa(statusCode))
	if statusCode != http.StatusOK {
		r.Header.Set("ErrorMessage", message)
	}
}

/*
updatePulicKeysPeriodic updates the cache periodically (every hour)
*/
func (a *oauth) updatePublicKeysPeriodic(keyURL string) {

	ticker := time.NewTicker(time.Hour)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				pk, err := getPublicKey(keyURL)
				if err == nil {
					a.setPkSafe(pk)
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

	/* Connect to the server to fetch Key details */
	r, err := http.Get(keyURL)
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
func (a *oauth) setPkSafe(pk *rsa.PublicKey) {
	a.rwMutex.Lock()
	a.gPkey = pk
	a.rwMutex.Unlock()
}

/*
getPkSafe returns the stored key (via a read lock)
*/
func (a *oauth) getPkSafe() *rsa.PublicKey {
	a.rwMutex.RLock()
	pk := a.gPkey
	a.rwMutex.RUnlock()
	return pk
}
