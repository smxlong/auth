package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const TEST_KEYSET = `{
    "keys": [
        {
            "kty": "oct",
            "use": "sig",
            "kid": "1",
            "k": "lchuyoxorUsi2drjZkazoLVfufIpI8lRs2iLpnJiTnw3vgZO2sWrKPS5EGJ9iy7ciTmJLCyvxF8IT-fZNApRZ0gOLQuPklgqiNNH47HQS6IPHdFqMDY-a6coQfdONMg2Pg5NpSqcrwHA74CE5D_Rh7wKkudlvubS7pkdygBxyc8s8rP3hRN0Gs7cMys5uEqTBOpZ19bCuXSRa3A_Iu6mkYriKlshKl5NJeJXiCGyzyI-a5qHX_Wfn8M3lkj_FUYm-0KKuH3G99d0j9FlyOwrcWhFruxXfPhTX9ihRXF8cF63jAdaXiZ7hnxI-IrxZko5aj1fiLAVGCo-tRRNkqPi7g",
            "alg": "HS256"
        },
				{
						"kty": "oct",
						"use": "sig",
						"kid": "2",
						"k": "pL-cuE8toS3pvm0iTvisJrRQro9Mm63Ji-oDfFyYD9vVMcme1ExPLN8Oa2jaLxM7aAs-ZHtBdWwcQ5noV3wne3kOi2qaX6wkWOOspJSwAAy36sZdXw7sVeEiP2Yo8qgSqMGoSsUzOFrNAwr2r6RlwWInOrtzS-4_H3Sx9stBxR5lfXrmqYDBsqB9b8u0heL2J911TYztsb93mXM0SdpUrqWyiKIEmkCPI0Cs41f-AuNgobbWBIPiUl88IZsO8wpQ2gpXeuAbGaeVzUsrYPPjEo-kIkSZUe_XpYgcTMTUWgZuQCNZhmYCEUBjAqFfdwZyFr9YMc7tiU9E1pKL49yxEQ",
						"alg": "HS256"
				}
    ]
}`

// testMiddleware returns a new Middleware with the test keyset
func testMiddleware(t *testing.T) *Middleware {
	m, err := NewMiddleware(
		WithRequiredAudience("test-audience"),
		WithRequiredIssuer("test-issuer"),
		WithKeySet(testKeySet(t)),
	)
	require.NoError(t, err)
	return m
}

// testKeySet returns the test keyset, loaded from a JSON string
func testKeySet(t *testing.T) jwk.Set {
	set, err := jwk.ParseString(TEST_KEYSET)
	require.NoError(t, err)
	return set
}

// testToken returns a signed test token
func testToken(t *testing.T, kid string) string {
	tk := jwt.New()
	tk.Set(jwt.AudienceKey, "test-audience")
	tk.Set(jwt.IssuerKey, "test-issuer")
	tk.Set(jwt.SubjectKey, "test-subject")
	iat := time.Now()
	nbf := iat
	exp := time.Now().Add(time.Hour)
	tk.Set(jwt.ExpirationKey, exp.Unix())
	tk.Set(jwt.IssuedAtKey, iat.Unix())
	tk.Set(jwt.NotBeforeKey, nbf.Unix())

	// Sign the token
	key, ok := testKeySet(t).LookupKeyID(kid)
	require.True(t, ok)
	alg, ok := key.Algorithm()
	require.True(t, ok)
	signed, err := jwt.Sign(tk, jwt.WithKey(alg, key))
	require.NoError(t, err)

	return string(signed)
}

// Test_parse tests the parsing of a token
func Test_parse(t *testing.T) {
	tk := testToken(t, "1")
	m := testMiddleware(t)
	token, err := m.parse(tk)
	require.NoError(t, err)
	require.NotNil(t, token)
	// now kid 2
	tk = testToken(t, "2")
	token, err = m.parse(tk)
	require.NoError(t, err)
	require.NotNil(t, token)
}

// Test_parse_audienceMismatch tests the parsing of a token with a mismatched audience
func Test_parse_audienceMismatch(t *testing.T) {
	tk := testToken(t, "1")
	m := testMiddleware(t)
	m.requiredAudience = "wrong-audience"

	_, err := m.parse(tk)
	require.Error(t, err)
}

// Test_parse_issuerMismatch tests the parsing of a token with a mismatched issuer
func Test_parse_issuerMismatch(t *testing.T) {
	tk := testToken(t, "1")
	m := testMiddleware(t)
	m.requiredIssuer = "wrong-issuer"

	_, err := m.parse(tk)
	require.Error(t, err)
}

// testRequestRecorder returns a (recorder, request) pair
func testRequestRecorder() (*httptest.ResponseRecorder, *http.Request) {
	return httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil)
}

// Test_Wrap tests that when we use the Wrap to wrap a http.Handler, the token in
// the Authorization header is parsed and added to the request context
func Test_Wrap(t *testing.T) {
	tk := testToken(t, "1")
	m := testMiddleware(t)

	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(ClaimsKey)
		require.NotNil(t, token)
	}))
	w, r := testRequestRecorder()
	r.Header.Set("Authorization", "Bearer "+tk)
	h.ServeHTTP(w, r)
}

// Test_Wrap_NoToken tests that when we use the Wrap to wrap a http.Handler, and no token
// is provided, the request is aborted with a 401 Unauthorized
func Test_Wrap_NoToken(t *testing.T) {
	m := testMiddleware(t)

	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(ClaimsKey)
		require.Nil(t, token)
	}))
	w, r := testRequestRecorder()
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// Test_Wrap_InvalidToken tests that when we use the Wrap to wrap a http.Handler, and an invalid token
// is provided, the request is aborted with a 401 Unauthorized
func Test_Wrap_InvalidToken(t *testing.T) {
	m := testMiddleware(t)

	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(ClaimsKey)
		require.Nil(t, token)
	}))
	w, r := testRequestRecorder()
	r.Header.Set("Authorization", "Bearer invalid-token")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// Test_Wrap_WrongAudience tests that when we use the Wrap to wrap a http.Handler, and a token
// with a wrong audience is provided, the request is aborted with a 401 Unauthorized
func Test_Wrap_WrongAudience(t *testing.T) {
	tk := testToken(t, "1")
	m := testMiddleware(t)
	m.requiredAudience = "wrong-audience"

	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(ClaimsKey)
		require.Nil(t, token)
	}))
	w, r := testRequestRecorder()
	r.Header.Set("Authorization", "Bearer "+tk)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// Test_Wrap_WrongIssuer tests that when we use the Wrap to wrap a http.Handler, and a token
// with a wrong issuer is provided, the request is aborted with a 401 Unauthorized
func Test_Wrap_WrongIssuer(t *testing.T) {
	tk := testToken(t, "1")
	m := testMiddleware(t)
	m.requiredIssuer = "wrong-issuer"

	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(ClaimsKey)
		require.Nil(t, token)
	}))
	w, r := testRequestRecorder()
	r.Header.Set("Authorization", "Bearer "+tk)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// Test_Handler tests that when we use the Handler to wrap a gin.HandlerFunc, the token in
// the Authorization header is parsed and added to the request context
func Test_Handler(t *testing.T) {
	tk := testToken(t, "1")
	m := testMiddleware(t)

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.Header.Set("Authorization", "Bearer "+tk)

	m.Handler(c)

	token, ok := c.Get(string(ClaimsKey))
	require.True(t, ok)
	require.NotNil(t, token)
}

// Test_Handler_NoToken tests that when we use the Handler to wrap a gin.HandlerFunc, and no token
// is provided, the request is aborted with a 401 Unauthorized
func Test_Handler_NoToken(t *testing.T) {
	m := testMiddleware(t)

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	m.Handler(c)

	require.Equal(t, http.StatusUnauthorized, c.Writer.Status())
}

// Test_Handler_InvalidToken tests that when we use the Handler to wrap a gin.HandlerFunc, and an invalid token
// is provided, the request is aborted with a 401 Unauthorized
func Test_Handler_InvalidToken(t *testing.T) {
	m := testMiddleware(t)

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.Header.Set("Authorization", "Bearer invalid-token")
	m.Handler(c)

	require.Equal(t, http.StatusUnauthorized, c.Writer.Status())
}

// Test_Handler_WrongAudience tests that when we use the Handler to wrap a gin.HandlerFunc, and a token
// with a wrong audience is provided, the request is aborted with a 401 Unauthorized
func Test_Handler_WrongAudience(t *testing.T) {
	tk := testToken(t, "1")
	m := testMiddleware(t)
	m.requiredAudience = "wrong-audience"

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.Header.Set("Authorization", "Bearer "+tk)
	m.Handler(c)

	require.Equal(t, http.StatusUnauthorized, c.Writer.Status())
}

// Test_Handler_WrongIssuer tests that when we use the Handler to wrap a gin.HandlerFunc, and a token
// with a wrong issuer is provided, the request is aborted with a 401 Unauthorized
func Test_Handler_WrongIssuer(t *testing.T) {
	tk := testToken(t, "1")
	m := testMiddleware(t)
	m.requiredIssuer = "wrong-issuer"

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.Header.Set("Authorization", "Bearer "+tk)
	m.Handler(c)

	require.Equal(t, http.StatusUnauthorized, c.Writer.Status())
}

// Test the keyprovider

// Test_newKeyProvider_KeySet tests the creation of a new keyprovider with
// a keyset
func Test_newKeyProvider_KeySet(t *testing.T) {
	o := &middlewareOptions{
		keyset: testKeySet(t),
	}
	kp, err := newKeyProvider(o)
	require.NoError(t, err)
	require.NotNil(t, kp)

	keyset, err := kp()
	require.NoError(t, err)
	require.NotNil(t, keyset)
}

// Test_newKeyProvider_JwksURL tests the creation of a new keyprovider with
// a jwksURL
func Test_newKeyProvider_JwksURL(t *testing.T) {
	o := &middlewareOptions{
		jwksURL: "https://www.googleapis.com/oauth2/v3/certs",
	}
	kp, err := newKeyProvider(o)
	require.NoError(t, err)
	require.NotNil(t, kp)

	keyset, err := kp()
	require.NoError(t, err)
	require.NotNil(t, keyset)

	// Should be at least 1 key
	require.NotEmpty(t, keyset.Keys)
}

// Test_newKeyProvider_OidcProvider tests the creation of a new keyprovider with
// an oidcProvider
func Test_newKeyProvider_OidcProvider(t *testing.T) {
	o := &middlewareOptions{
		oidcProvider: "https://accounts.google.com",
	}
	kp, err := newKeyProvider(o)
	require.NoError(t, err)
	require.NotNil(t, kp)

	keyset, err := kp()
	require.NoError(t, err)
	require.NotNil(t, keyset)

	// Should be at least 1 key
	require.NotEmpty(t, keyset.Keys)
}
