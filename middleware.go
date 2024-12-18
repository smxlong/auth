package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// keyProvider yields a keyset.
type keyProvider func() (jwk.Set, error)

// Middleware implements authentication/authorization middleware.
type Middleware struct {
	requiredAudience string
	requiredIssuer   string
	kp               keyProvider
}

// middlewareOptions contains options for the middleware.
type middlewareOptions struct {
	// initializationContext to use during initialization if any
	initializationContext context.Context
	// requiredAudience is the required audience for the token.
	requiredAudience string
	// requiredIssuer is the required issuer for the token.
	requiredIssuer string
	// oidcProvider is the OIDC provider to use. If set, this is used to
	// populate the JWKS URL.
	oidcProvider string
	// jwksURL is the JWKS URL to use. If set, this is used to populate the
	// keyset.
	jwksURL string
	// keyset is the keyset to use. If set, this is used to validate the token.
	keyset jwk.Set
}

// MiddlewareOption is a function that configures a middleware.
type MiddlewareOption func(*middlewareOptions) error

// parse options
func (o *middlewareOptions) apply(opts ...MiddlewareOption) error {
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return err
		}
	}
	return nil
}

// NewMiddleware creates a new Middleware.
func NewMiddleware(opts ...MiddlewareOption) (*Middleware, error) {
	o := &middlewareOptions{}
	if err := o.apply(opts...); err != nil {
		return nil, err
	}
	kp, err := newKeyProvider(o)
	if err != nil {
		return nil, err
	}
	return &Middleware{
		requiredAudience: o.requiredAudience,
		requiredIssuer:   o.requiredIssuer,
		kp:               kp,
	}, nil
}

// WithInitializationContext sets the initialization context for the middleware.
func WithInitializationContext(ctx context.Context) MiddlewareOption {
	return func(o *middlewareOptions) error {
		o.initializationContext = ctx
		return nil
	}
}

// WithRequiredAudience sets the required audience for the middleware.
func WithRequiredAudience(audience string) MiddlewareOption {
	return func(o *middlewareOptions) error {
		o.requiredAudience = audience
		return nil
	}
}

// WithRequiredIssuer sets the required issuer for the middleware.
func WithRequiredIssuer(issuer string) MiddlewareOption {
	return func(o *middlewareOptions) error {
		o.requiredIssuer = issuer
		return nil
	}
}

// WithOIDCProvider sets the OIDC provider for the middleware.
func WithOIDCProvider(oidcProvider string) MiddlewareOption {
	return func(o *middlewareOptions) error {
		o.oidcProvider = oidcProvider
		return nil
	}
}

// WithJWKSURL sets the JWKS URL for the middleware. This takes precedence over
// the OIDC provider.
func WithJWKSURL(jwksURL string) MiddlewareOption {
	return func(o *middlewareOptions) error {
		o.jwksURL = jwksURL
		return nil
	}
}

// WithKeySet sets the keyset for the middleware. This takes precedence over
// the JWKS URL and OIDC provider.
func WithKeySet(keyset jwk.Set) MiddlewareOption {
	return func(o *middlewareOptions) error {
		o.keyset = keyset
		return nil
	}
}

// parse parses an incoming token, validates it, and returns the claims.
func (m *Middleware) parse(token string) (jwt.Token, error) {
	// Parse the token
	keyset, err := m.kp()
	if err != nil {
		return nil, err
	}
	tok, err := jwt.ParseString(token,
		jwt.WithKeySet(keyset),
		jwt.WithAudience(m.requiredAudience),
		jwt.WithIssuer(m.requiredIssuer),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

// Token is our interface to the token
type Token interface {
	Get(key string, v interface{}) error
}

// contextKey is a type for context keys.
type contextKey string

// ClaimsKey is the context key for the claims.
const ClaimsKey contextKey = "claims"

// tokenFromHeader returns the token from the Authorization header.
func tokenFromHeader(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// Wrap wraps an http.Handler with the authentication middleware.
func (m *Middleware) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := tokenFromHeader(r)
		if t == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		token, err := m.parse(t)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ClaimsKey, token)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Handler is a gin.HandlerFunc that implements the authentication middleware.
func (m *Middleware) Handler(c *gin.Context) {
	t := tokenFromHeader(c.Request)
	if t == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
		return
	}
	token, err := m.parse(t)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.Set(string(ClaimsKey), token)
	c.Next()
}
