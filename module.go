package caddy_pow

import (
	"embed"
	"net/http"
	"strconv"
	"strings"

	_ "embed"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

var (
	//go:embed static
	staticFs embed.FS
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("pow", parseCaddyfile)
	// before handlers that typically respond to requests
	httpcaddyfile.RegisterDirectiveOrder("pow", httpcaddyfile.Before, "abort")
}

// Gizmo is an example; put your own type here.
type Middleware struct {
	_logger *zap.Logger

	Difficulty int    `json:"difficulty,omitempty"`
	RobotsTxt  bool   `json:"robots_txt,omitempty"`
	CookieName string `json:"cookie_name,omitempty"`

	server *Server

	metrics Metrics
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.pow",
		New: func() caddy.Module {
			return &Middleware{
				Difficulty: 4,
				CookieName: "pow",
			}
		},
	}
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := Middleware{}.CaddyModule().New().(*Middleware)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Middleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, handler caddyhttp.Handler) error {
	server := m.Server()

	path := r.URL.Path

	switch {
	case (path == "/robots.txt" || path == "/.well-known/route.txt") && m.RobotsTxt:
		http.ServeFileFS(rw, r, staticFs, "static/robots.txt")
		return nil
	case strings.HasPrefix(path, "/.within.website/"):
		server.ServeHTTP(rw, r)
		return nil
	}

	if should, err := server.ShouldChallenge(r); should {
		m.logger().Debug("should challenge", zap.Error(err))
		if err != nil {
			server.renderError(rw, r, http.StatusOK, err)
		} else {
			server.renderIndex(rw, r)
		}
		return nil
	}

	handler.ServeHTTP(rw, r)
	return nil
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	m._logger = ctx.Logger(m)
	m.registerMetrics(ctx)

	return nil
}

func (m *Middleware) logger() *zap.Logger {
	if m._logger == nil {
		m._logger = zap.NewNop()
	}
	return m._logger
}

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			directive := d.Val()
			m.logger().Debug("UnmarshalCaddyfile", zap.String("directive", directive))
			switch directive {
			case "cookie_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.CookieName = d.Val()
			case "difficulty":
				if !d.NextArg() {
					return d.ArgErr()
				}
				res, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("difficulty must be an integer")
				}
				m.Difficulty = res
			case "robots_txt":
				m.RobotsTxt = true
			default:
				return d.Errf("unknown directive: %s", directive)
			}
		}
	}
	m.logger().Debug("UnmarshalCaddyfile", zap.Any("m", m))
	return nil
}

var (
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
