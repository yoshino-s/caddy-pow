# Caddy Pow

> Inspired by https://github.com/Xe/x/blob/master/cmd/anubis/

A pow(Proof of Work) based Web Application Firewall(WAF) for Caddy server.

More description can be found at https://xeiaso.net/blog/2025/anubis/ . This is a port from the anubis single binary to caddy plugin.

Example: https://httpbin.yoshino-s.xyz/

## Installation

```bash
xcaddy build --with github.com/yoshino-s/caddy-pow
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
