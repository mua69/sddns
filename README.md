# sddns

Simple dynamic DNS (DDNS) server written in Go.

`sddns` runs an HTTP endpoint that clients (for example a home router) call to
tell it their current IP addresses. The server checks the request against a
per-host password and updates the host's `A` and/or `AAAA` records on a DNS
server using `nsupdate` (RFC 2136 dynamic updates, as supported by BIND and others).

## Features

- HTTP update endpoint: `GET /update?fqdn=...&pass=...&ipv4=...&ipv6=...`
- Updates IPv4 (`A`) and IPv6 (`AAAA`) records independently
- **IPv6 interface merging:** takes the network prefix from the reported IPv6
  address and adds a fixed interface ID you configure. This lets a router
  report its own address while the DNS record points to a different host
  behind it.
- In-memory cache of the last address for each host, so `nsupdate` runs only
  when an address actually changes
- Several hosts per server, each with its own password (stored only as a salted hash)

## Requirements

- Go 1.24 or newer, to build
- `nsupdate` (from BIND's `dnsutils` / `bind-utils`) on the server host
- A DNS server that allows dynamic updates for the zone, plus a TSIG key file
  that `nsupdate -k` accepts
- A reverse proxy with TLS (nginx, Caddy, ...) on the same host. sddns listens
  only on `127.0.0.1` and is not reachable without one.

## Building

```sh
go build -o sddns .
go test ./...        # run the tests
```

## Usage

```sh
sddns <config file>                  # run the update server
sddns -dryrun <config file>          # run without changing DNS (see below)
sddns -genpass <fqdn> <config file>  # create or replace a client's password
```

`sddns` starts the HTTP update server on `127.0.0.1:<Port>` and runs until it
is stopped. The listen address is fixed so the server can never be exposed
directly; see [Reverse proxy](#reverse-proxy). It exits at
startup if the config has no `Clients`, a client has no valid `PasswordHash`,
or `NsupdateKey` is missing.

### Dry run

With `-dryrun`, sddns handles requests normally (password check, address
validation, IPv6 merging) but doesn't run `nsupdate`. It logs the script it
would have sent:

```
level=INFO msg="dry run: nsupdate not executed" fqdn=home.example.org type=A addr=203.0.113.7 script="server localhost\ndel home.example.org in a\nadd home.example.org 300 in a 203.0.113.7\nsend\n"
```

This is useful to test a new client or router setup. `NsupdateKey` isn't
checked in this mode. The in-memory cache is still updated, so a repeated
request with the same address logs nothing new, just as in normal operation.

### Client passwords

Passwords are stored only as salted PBKDF2-SHA256 hashes. To create a password
for a client:

```sh
$ sddns -genpass home.example.org server.json
Replaced password of client home.example.org in server.json.
Password: GLC4OXQSRBCCYLKDUUGIJ5O5U2
The password is not stored in cleartext and cannot be shown again.
Restart sddns to apply the change.
```

- The password is random: 26 characters (A–Z, 2–7), about 130 bits. It can be
  used in a URL without escaping.
- Its hash is written to the client's `PasswordHash`. If no client with that
  `Fqdn` exists, one is added.
- Copy the password into the client (for example the router's DynDNS
  settings). It is shown only once; if it is lost, run `-genpass` again.
- The config file is rewritten as formatted JSON. Settings are kept, but the
  command refuses to run if the file contains fields it doesn't know, so
  nothing is dropped by accident.
- Restart the server afterwards; the config is read only at startup.

Configs from older versions with a cleartext `Key` are rejected at startup.
Running `-genpass` for that client replaces the `Key` with a `PasswordHash`.

### Configuration

Example (`server.json`):

```json
{
  "Port": 3200,
  "NsupdateCmd": "/usr/bin/nsupdate",
  "NsupdateKey": "/etc/bind/ddns.key",
  "NsupdateServer": "localhost",
  "NsupdateTTL": 300,
  "Clients": [
    {
      "Fqdn": "home.example.org",
      "PasswordHash": "pbkdf2-sha256$100000$iRF/2j4Nq6NjBRup4jPgzw$QQanseYszPe16nd9hBUcLQC0568fa2lSVjE7B8QTJCY",
      "Ipv6Interface": "211:32ff:fe12:3456"
    }
  ]
}
```

| Field            | Default             | Description                                                  |
|------------------|---------------------|--------------------------------------------------------------|
| `Port`           | `3200`              | Port the HTTP server listens on (always on `127.0.0.1`)      |
| `NsupdateCmd`    | `/usr/bin/nsupdate` | Path to the `nsupdate` binary                                |
| `NsupdateKey`    | —                   | TSIG key file passed to `nsupdate -k` (**required**; the server won't start if it is missing or unreadable) |
| `NsupdateServer` | `localhost`         | DNS server that receives the updates                         |
| `NsupdateTTL`    | `300`               | TTL of the created records, in seconds                       |
| `TrustProxy`     | `true`              | Log the client IP from the `X-Real-Ip` header set by the reverse proxy. If set to `false`, every request is logged as `client=127.0.0.1` |
| `Debug`          | `false`             | Also log debug messages (configured clients, nsupdate output)  |
| `Clients`        | —                   | List of hosts that may be updated (see below)                |

Fields for each client:

| Field           | Description                                                                                 |
|-----------------|---------------------------------------------------------------------------------------------|
| `Fqdn`          | Fully qualified host name whose records are updated                                         |
| `PasswordHash`  | Required. Hash of the password the client sends as `pass`. Create it with `-genpass` |
| `Ipv6Interface` | Optional. The trailing groups of the IPv6 address to use, e.g. `211:32ff:fe12:3456` (1–7 groups) |

### Update request

```
GET https://<proxy host>/update?fqdn=<fqdn>&pass=<pass>[&ipv4=<ipv4>][&ipv6=<ipv6>]
```

- `fqdn` and `pass` are required.
- `ipv4` and `ipv6` are both optional, and each record is updated only when
  its parameter is given. The server does **not** take the address from the
  connection, so the client must always send it.
- Both addresses are validated. An invalid value is rejected, its record isn't
  touched, and the response is `fail`.
- The response is `ok` on success and `fail` if `nsupdate` failed. A plain
  error message is returned for a missing or wrong `fqdn`/`pass`.

For each changed address the server sends this to `nsupdate`:

```
server <NsupdateServer>
del <fqdn> in a|aaaa
add <fqdn> <TTL> in a|aaaa <address>
send
```

#### Example: router custom DynDNS URL

Many routers (for example AVM FRITZ!Box) let you set a custom DynDNS update
URL with placeholders:

```
https://ddns.example.org/update?fqdn=<domain>&pass=<pass>&ipv4=<ipaddr>&ipv6=<ip6addr>
```

The router sends its own IPv6 address. With `Ipv6Interface` set, sddns keeps
the prefix from that address and swaps in the configured interface ID. The
`AAAA` record then points to a particular device in the LAN.

Instead of its own address, the router can send its LAN prefix, for example
`ipv6=<ip6lanprefix>` on a FRITZ!Box, which arrives as
`2001:9e8:8cc2:4900::/64`. sddns accepts prefixes in this CIDR notation too;
see below.

#### IPv6 interface merging in detail

If `Ipv6Interface` has *N* groups, sddns keeps the first `8 - N` groups of the
reported address and appends the configured groups:

```
reported:   2001:db8:1234:5600:abcd:ef01:2345:6789
interface:                     211:32ff:fe12:3456   (N = 4)
result:     2001:db8:1234:5600:211:32ff:fe12:3456
```

The reported address can use any valid IPv6 notation, including the compressed
`::` form. An invalid address is rejected and the response is `fail`.

**Prefixes** (`<address>/<length>`) are merged bit by bit: the first *length*
bits come from the prefix, all remaining bits from `Ipv6Interface`:

```
reported:   2001:9e8:8cc2:4900::/64
interface:                      211:32ff:fe12:3456
result:     2001:9e8:8cc2:4900:211:32ff:fe12:3456
```

`Ipv6Interface` must cover every bit after the prefix, so a /64 needs at least
4 groups and a /56 at least 5. Otherwise the request is rejected (`fail`)
rather than creating an address with zeros in it. With a shorter prefix, the
extra interface groups select the subnet: for a /56, the interface
`7:211:32ff:fe12:3456` turns `2001:9e8:8cc2:4900::/56` into
`2001:9e8:8cc2:4907:211:32ff:fe12:3456`. Bits inside the prefix are never
overwritten. Write
`Ipv6Interface` as 1–7 hex groups without `::`; the server refuses to start if
it is malformed.

## Running as a service

A systemd unit is in [contrib/systemd/sddns.service](contrib/systemd/sddns.service).
It runs sddns as an unprivileged `sddns` user with systemd sandboxing, reads
`/etc/sddns/server.json` and logs to the journal (`journalctl -u sddns`). The
install steps are in the comments at the top of the file.

The unit adds the `bind` group so sddns can read the TSIG key file; change
`SupplementaryGroups` if your key file belongs to a different group. After
`-genpass`, run `systemctl restart sddns` to load the new password.

## Reverse proxy

sddns speaks plain HTTP on `127.0.0.1` only. A reverse proxy on the same host
terminates TLS and forwards `/update`. A complete nginx config with rate
limiting is in [contrib/nginx/sddns.conf](contrib/nginx/sddns.conf). The
essential part:

```nginx
location = /update {
    limit_req zone=sddns burst=5 nodelay;
    proxy_pass http://127.0.0.1:3200;
    proxy_set_header X-Real-IP $remote_addr;
}
```

sddns logs the real client IP from `X-Real-IP` (`TrustProxy`, on by default).
The proxy must always set this header itself (as above), overwriting any value
the client sent; otherwise a client could put any IP into the logs. If the
header is missing, the connection address (`127.0.0.1`) is logged.

Turn off the proxy's access log for this location (`access_log off;`), or strip
the query string from it: otherwise the proxy writes passwords to disk.

### Rate limiting

The nginx example limits each client IP to 6 requests per minute, with a burst
of 5. Requests over the limit are rejected with `429 Too Many Requests` before
they reach sddns. A router sends updates only when its address changes, so
this is generous. The limit mainly caps CPU load (each password check costs
about 14 ms) and log noise; guessing a generated password is hopeless anyway.

`limit_req_zone` must be in nginx's `http` context. Files in
`/etc/nginx/conf.d/` are included there, so the contrib file can be copied
there as is. To check it:

```sh
sudo nginx -t && sudo systemctl reload nginx
for i in $(seq 10); do
  curl -s -o /dev/null -w "%{http_code}\n" "https://ddns.example.org/update?fqdn=x&pass=y"
done   # the first requests pass, the rest return 429
```

If another proxy or CDN sits in front of nginx, configure `set_real_ip_from`
and `real_ip_header` first, so the limit and `X-Real-IP` use the real client
address.

### fail2ban

fail2ban adds a second layer: it bans IPs that keep failing to log in. A filter
and a jail for the sddns log format are in
[contrib/fail2ban/](contrib/fail2ban/):

```sh
sudo cp contrib/fail2ban/filter.d/sddns.conf /etc/fail2ban/filter.d/
sudo cp contrib/fail2ban/jail.d/sddns.conf   /etc/fail2ban/jail.d/
sudo fail2ban-regex systemd-journal[journalflags=1] /etc/fail2ban/filter.d/sddns.conf
sudo systemctl reload fail2ban
sudo fail2ban-client status sddns
```

- The filter matches wrong passwords, unknown host names and requests with
  missing parameters. It reads the IP from the trailing `client=` field, so a
  crafted host name can't get a different address banned.
- The jail bans an IP for 1 hour after 5 failures within 10 minutes, on the
  HTTP and HTTPS ports where nginx accepts requests.
- It assumes sddns runs as the systemd unit `sddns.service` and logs to the
  journal. For a log file, replace `backend`/`journalmatch` with `logpath`.
- `TrustProxy` must stay on, otherwise every failure is logged as
  `client=127.0.0.1` and fail2ban would ban localhost.

## Logging

sddns writes structured `key=value` log lines to stderr, using Go's standard
`log/slog`:

```
time=2026-11-08T18:30:02.532+01:00 level=INFO msg="updated A record" fqdn=home.example.org ipv4=203.0.113.7
time=2026-11-08T18:30:02.532+01:00 level=ERROR msg="invalid fqdn or passphrase" fqdn=home.example.org client=198.51.100.23
```

Values with special characters are quoted and escaped, so a client can't fake
extra log lines. Failed logins always log `client=<ip>`, which makes them easy
to match in fail2ban (see [fail2ban](#fail2ban)).

## Security notes

- sddns binds only to `127.0.0.1`. The password travels in the URL query
  string, so the reverse proxy must use TLS.
- Passwords are generated randomly by `-genpass` and stored only as PBKDF2 hashes, so a leaked config file does not reveal them.
- Passwords are never logged. Failed logins are logged with the client IP,
  so tools like fail2ban can block repeated guessing.
- Limit the TSIG key on the DNS server so it can update only the client host
  names and only `A`/`AAAA` records. In BIND:
  `update-policy { grant ddns-key name home.example.org. A AAAA; };`
- The cache lives only in memory. After a restart, the first update for each
  host always runs `nsupdate`.

## License

MIT, see [LICENSE](LICENSE).
