package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// newKeyProvider creates the keyprovider
func newKeyProvider(o *middlewareOptions) (keyProvider, error) {
	// Use the provided context or create a new one
	ctx := o.initializationContext
	if ctx == nil {
		ctx = context.Background()
	}
	switch {
	// If keyset is set, return the keyset
	case o.keyset != nil:
		return func() (jwk.Set, error) {
			return o.keyset, nil
		}, nil
		// If jwksURL is set, create a new cache and return the keyset from the
		// cache
	case o.jwksURL != "":
		cache, err := jwk.NewCache(ctx, httprc.NewClient())
		if err != nil {
			return nil, err
		}
		if err := cache.Register(ctx, o.jwksURL); err != nil {
			return nil, err
		}
		return func() (jwk.Set, error) {
			return cache.Lookup(ctx, o.jwksURL)
		}, nil
		// If oidcProvider is set, create a new cache and return the keyset from the
		// cache
	case o.oidcProvider != "":
		jwksURL, err := fetchJWKSURL(ctx, o.oidcProvider)
		if err != nil {
			return nil, err
		}
		cache, err := jwk.NewCache(ctx, httprc.NewClient())
		if err != nil {
			return nil, err
		}
		if err := cache.Register(ctx, jwksURL); err != nil {
			return nil, err
		}
		return func() (jwk.Set, error) {
			return cache.Lookup(ctx, jwksURL)
		}, nil
	}
	// no keyset provided, so no keyprovider, but also no error
	return nil, nil
}

// fetchJWKSURL fetches the JWKS URL from the OIDC provider
func fetchJWKSURL(ctx context.Context, oidcProvider string) (string, error) {
	wellKnownURL := strings.TrimSuffix(oidcProvider, "/") + "/.well-known/openid-configuration"
	r, err := http.NewRequestWithContext(ctx, "GET", wellKnownURL, nil)
	if err != nil {
		return "", err
	}
	wellKnownResponse, err := http.DefaultClient.Do(r)
	if err != nil {
		return "", err
	}
	defer wellKnownResponse.Body.Close()
	var wellKnown struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(wellKnownResponse.Body).Decode(&wellKnown); err != nil {
		return "", err
	}
	return wellKnown.JWKSURI, nil
}
