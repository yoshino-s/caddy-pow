package caddy_pow

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

func (v *Server) calculateChallenge(r *http.Request) string {
	fp := sha256.Sum256(v.priv.Seed())

	data := fmt.Sprintf(
		"Accept-Encoding=%s,Accept-Language=%s,X-Real-IP=%s,User-Agent=%s,WeekTime=%s,Fingerprint=%x",
		r.Header.Get("Accept-Encoding"),
		r.Header.Get("Accept-Language"),
		getClientIP(r),
		r.UserAgent(),
		time.Now().UTC().Round(24*7*time.Hour).Format(time.RFC3339),
		fp,
	)
	result, _ := sha256sum(data)

	v.logger.Debug("challenge calculated", zap.String("data", data), zap.String("challenge", result))

	return result
}

func (v *Server) GetChallenge(r *http.Request) string {
	result := v.calculateChallenge(r)

	v.middleware.metrics.challengesIssued.Inc()

	v.logger.Debug("challenge issued", zap.String("challenge", result), zap.Int("difficulty", v.middleware.Difficulty))
	return result
}

func (v *Server) ShouldChallenge(r *http.Request) (bool, error) {
	switch {
	case !strings.Contains(r.UserAgent(), "Mozilla"):
		v.middleware.metrics.bypasses.Inc()
		v.logger.Debug("non-browser user agent")
		return false, nil
	case strings.HasPrefix(r.URL.Path, "/.well-known/"):
		v.middleware.metrics.bypasses.Inc()
		v.logger.Debug("well-known path")
		return false, nil
	case strings.HasSuffix(r.URL.Path, ".rss") || strings.HasSuffix(r.URL.Path, ".xml") || strings.HasSuffix(r.URL.Path, ".atom"):
		v.middleware.metrics.bypasses.Inc()
		v.logger.Debug("rss path")
		return false, nil
	case r.URL.Path == "/favicon.ico":
		v.middleware.metrics.bypasses.Inc()
		v.logger.Debug("favicon path")
		return false, nil
	case r.URL.Path == "/robots.txt":
		v.middleware.metrics.bypasses.Inc()
		v.logger.Debug("robots.txt path")
		return false, nil
	}

	cookie, err := r.Cookie(v.middleware.CookieName)
	if err != nil {
		v.logger.Debug("cookie not found", zap.String("path", r.URL.Path))
		return true, nil
	}

	if err := cookie.Valid(); err != nil {
		v.logger.Debug("cookie is invalid", zap.Error(err))
		return true, nil
	}

	if time.Now().After(cookie.Expires) && !cookie.Expires.IsZero() {
		v.logger.Debug("cookie expired", zap.String("path", r.URL.Path))
		return true, nil
	}

	token, err := jwt.ParseWithClaims(cookie.Value, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return v.pub, nil
	})

	if err != nil || !token.Valid {
		v.logger.Debug("invalid token", zap.String("path", r.URL.Path))
		return true, nil
	}
	claims := token.Claims.(jwt.MapClaims)

	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().After(time.Unix(int64(exp), 0)) {
			v.logger.Debug("token expired", zap.String("path", r.URL.Path))
			return true, nil
		}
	} else {
		v.logger.Debug("missing exp claim", zap.String("path", r.URL.Path))
		return true, nil
	}

	challenge := v.calculateChallenge(r)

	if claims["challenge"] != challenge {
		v.logger.Debug("challenge mismatch", zap.String("path", r.URL.Path))
		return true, nil
	}

	var nonce int

	if v, ok := claims["nonce"].(float64); ok {
		nonce = int(v)
	}

	calcString := fmt.Sprintf("%s%d", challenge, nonce)
	calculated, err := sha256sum(calcString)
	if err != nil {
		v.logger.Error("failed to calculate sha256sum", zap.String("path", r.URL.Path), zap.Error(err))
		return true, err
	}

	if subtle.ConstantTimeCompare([]byte(claims["response"].(string)), []byte(calculated)) != 1 {
		v.logger.Debug("invalid response", zap.String("path", r.URL.Path))
		v.middleware.metrics.failedValidations.Inc()
		return true, nil
	}

	return false, nil
}

func (v *Server) VerifyChallenge(r *http.Request) (string, int, error) {
	nonceStr := r.FormValue("nonce")
	if nonceStr == "" {
		return "", http.StatusBadRequest, fmt.Errorf("missing nonce")
	}

	elapsedTimeStr := r.FormValue("elapsedTime")
	if elapsedTimeStr == "" {
		return "", http.StatusBadRequest, fmt.Errorf("missing elapsedTime")
	}

	elapsedTime, err := strconv.ParseFloat(elapsedTimeStr, 64)
	if err != nil {
		return "", http.StatusBadRequest, fmt.Errorf("invalid elapsedTime")
	}

	difficultyStr := r.FormValue("difficulty")
	if difficultyStr == "" {
		return "", http.StatusBadRequest, fmt.Errorf("missing difficulty")
	}

	difficulty, err := strconv.Atoi(difficultyStr)
	if err != nil {
		return "", http.StatusBadRequest, fmt.Errorf("invalid difficulty")
	}

	zap.L().Info("challenge took", zap.Float64("elapsedTime", elapsedTime))
	v.middleware.metrics.timeTaken.Observe(elapsedTime)

	response := r.FormValue("response")

	challenge := v.calculateChallenge(r)

	nonce, err := strconv.Atoi(nonceStr)
	if err != nil {
		return "", http.StatusBadRequest, fmt.Errorf("invalid nonce")
	}

	calcString := fmt.Sprintf("%s%d", challenge, nonce)
	calculated, err := sha256sum(calcString)
	if err != nil {
		return "", http.StatusInternalServerError, fmt.Errorf("failed to calculate response")
	}

	if subtle.ConstantTimeCompare([]byte(response), []byte(calculated)) != 1 {
		v.middleware.metrics.failedValidations.Inc()
		return "", http.StatusForbidden, fmt.Errorf("invalid response")
	}

	// compare the leading zeroes
	if !strings.HasPrefix(response, strings.Repeat("0", difficulty)) {
		v.middleware.metrics.failedValidations.Inc()
		return "", http.StatusForbidden, fmt.Errorf("invalid response")
	}

	// generate JWT cookie
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"challenge": challenge,
		"nonce":     nonce,
		"response":  response,
		"iat":       time.Now().Unix(),
		"nbf":       time.Now().Add(-1 * time.Minute).Unix(),
		"exp":       time.Now().Add(24 * 7 * time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(v.priv)
	if err != nil {
		return "", http.StatusInternalServerError, fmt.Errorf("failed to sign token")
	}

	v.middleware.metrics.challengesValidated.Inc()

	return tokenString, http.StatusOK, nil
}

func sha256sum(text string) (string, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(text))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func getClientIP(r *http.Request) string {
	if v, ok := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]any); ok {
		if ip, ok := v[caddyhttp.ClientIPVarKey].(string); ok {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return host
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}
