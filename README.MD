# Caddy Waf

> Inspired by https://github.com/Xe/x/blob/master/cmd/anubis/

A pow(Proof of Work) based Web Application Firewall(WAF) for Caddy server.

## Installation

```bash
xcaddy build --with github.com/yoshino-x/caddy-waf
```

## Usage

Simple

```caddy
:8080 {
    pow
    reverse_proxy 127.0.0.1:3000
}
```

With Configs

```caddy
:8080 {
    pow {
        robots_txt # enable /robots.txt to ban ai spider
        difficulty 4 # set pow difficulty, default 4
        cookie_name "pow" # set pow cookie name, default "pow"
    }
    reverse_proxy 127.0.0.1:3000
}
```