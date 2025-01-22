package caddy_pow

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"time"

	"github.com/a-h/templ"
	"go.uber.org/zap"
	"within.website/x/xess"
)

//go:generate go run github.com/a-h/templ/cmd/templ@latest generate

var (
	_ http.Handler = (*Server)(nil)
)

func (m *Middleware) Server() *Server {
	if m.server == nil {
		m.server = NewServer(m)
	}
	return m.server
}

type Server struct {
	http.ServeMux

	priv ed25519.PrivateKey
	pub  ed25519.PublicKey

	middleware *Middleware
	logger     *zap.Logger
}

func NewServer(middleware *Middleware) *Server {
	pub, priv, _ := ed25519.GenerateKey(nil)

	s := &Server{
		ServeMux: *http.NewServeMux(),

		priv: priv,
		pub:  pub,

		middleware: middleware,
		logger:     middleware.logger(),
	}

	s.Handle("/.within.website/x/cmd/anubis/", http.StripPrefix("/.within.website/x/cmd/anubis", http.FileServerFS(staticFs)))

	xess.Mount(&s.ServeMux)

	s.HandleFunc("POST /.within.website/x/cmd/anubis/api/make-challenge", s.MakeChallenge)
	s.HandleFunc("GET /.within.website/x/cmd/anubis/api/pass-challenge", s.PassChallenge)
	s.HandleFunc("GET /.within.website/x/cmd/anubis/api/test-error", s.testError)

	return s
}

func (s *Server) MakeChallenge(w http.ResponseWriter, r *http.Request) {
	challenge := s.GetChallenge(r)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(struct {
		Challenge  string `json:"challenge"`
		Difficulty int    `json:"difficulty"`
	}{
		Challenge:  challenge,
		Difficulty: s.middleware.Difficulty,
	})
}

func (s *Server) PassChallenge(w http.ResponseWriter, r *http.Request) {
	token, status, err := s.VerifyChallenge(r)
	if err != nil {
		s.clearCookie(w)
		s.renderError(w, r, status, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     s.middleware.CookieName,
		Value:    token,
		Expires:  time.Now().Add(24 * 7 * time.Hour),
		SameSite: http.SameSiteDefaultMode,
		Path:     "/",
	})

	redirect := r.FormValue("redirect")
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    s.middleware.CookieName,
		Value:   "",
		Expires: time.Now().Add(-1 * time.Hour),
		MaxAge:  -1,
	})
}

func (s *Server) renderIndex(w http.ResponseWriter, r *http.Request) {
	templ.Handler(
		base("Making sure you're not a bot!", index()),
	).ServeHTTP(w, r)
}

func (s *Server) testError(w http.ResponseWriter, r *http.Request) {
	err := r.FormValue("err")
	templ.Handler(base("Oh noes!", errorPage(err)), templ.WithStatus(http.StatusInternalServerError)).ServeHTTP(w, r)
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, code int, err error) {
	templ.Handler(base("Oh noes!", errorPage(err.Error())), templ.WithStatus(code)).ServeHTTP(w, r)
}
