# Entra CBA ID Generator

A self-hosted HTTPS tool for inspecting client certificates and generating all [Microsoft Entra ID Certificate-Based Authentication (CBA)](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication) `certificateUserIDs` from a presented certificate.

Connect with your client certificate and the tool displays every CBA mapping format Entra supports — useful for debugging CBA configuration, validating certificate attributes, and determining which `certificateUserID` value to configure on a user object.

## Features

- Accepts mTLS connections and extracts the presented client certificate
- Displays all 7 Entra CBA `certificateUserID` formats:
  - `IssuerAndSubject` — `X509:<I>[issuer]<S>[subject]`
  - `RFC822Name` — `X509:<RFC822>[email]`
  - `Subject` — `X509:<Subject>[subject]`
  - `SKI` — `X509:<SKI>[hex]`
  - `PrincipalName` — `X509:<PN>[upn]` (from OtherName SAN)
  - `SHA1PublicKey` — `X509:<SHA1>[hex]`
  - `IssuerAndSerialNumber` — `X509:<I>[issuer]<SR>[reversed_serial_hex]`
- Shows full certificate details: subject, issuer, validity, SANs, fingerprint
- Automatically obtains and renews a TLS certificate via Let's Encrypt (TLS-ALPN-01)

## Usage

> **Note:** To satisfy the TLS-ALPN-01 challenge for certificate issuance and renewal, this server must be reachable on port **443** from the internet. If you cannot run this server directly on port 443, you will need a TCP load balancer or reverse proxy in front of it to forward traffic from port 443 to the server's listening port (default 8559).

> **Warning:** This tool is intended for testing and debugging CBA configurations. It has not been extensively tested for use in production environments.

### Binary

```bash
entra-cba-id-generator -domain certuserid.example.com
```

Flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-domain` | `localhost` | Domain to obtain a Let's Encrypt certificate for |
| `-port` | `8559` | Port to listen on for HTTPS connections |
| `-https-redirect-port` | `0` (disabled) | If set, listens on this port for HTTP and redirects to HTTPS |
| `-https-redirect-target-port` | `443` | Target port for HTTPS redirection (used with `-https-redirect-port`). This should be the public-facing port, not necessarily the server's listening port. |
| `-staging` | `false` | Use the Let's Encrypt staging environment (avoids rate limits during testing) |
| `-local-cert` | `false` | Use a local self-signed certificate instead of obtaining one from ACME (for testing) |

Open `https://<domain>:<port>/` in a browser (or with curl) while presenting a client certificate.

### Docker

```bash
docker run -d \
  -p 8559:8559 \
  -v entra-acme:/.acme \
  ghcr.io/<owner>/entra-cba-id-generator:latest \
  -domain certuserid.example.com
```

The `/.acme` volume persists the Let's Encrypt account credentials and certificate across container restarts.

### Docker Compose

```yaml
services:
  entra-cba-id-generator:
    image: ghcr.io/<owner>/entra-cba-id-generator:latest
    command: [
      "-domain", 
      "certuserid.example.com"
      # Additional flags can be added here, e.g. "-staging", "-port", etc.
      # "-https-redirect-port", "80",
      # "-https-redirect-target-port", "443"
    ]
    ports:
      # Using an external load balancer or NAT
      - "8559:8559"
      # Exposing port 443 directly (not recommended, requires running as root or with CAP_NET_BIND_SERVICE)
      # - "443:443"
      # Optional HTTP to HTTPS redirection
      # - "80:80"
    volumes:
      - entra-acme:/.acme
    restart: unless-stopped

volumes:
  entra-acme:
```

Replace `<owner>` with the GitHub organisation or user that owns the package. Additional flags (e.g. `-staging`, `-port`) can be appended to the `command` list.

### Example with curl

```bash
curl --cert client.crt --key client.key \
     https://certuserid.example.com:8559/
```

## Requirements

- Port **443** must be reachable from the internet for the TLS-ALPN-01 ACME challenge (certificate issuance and renewal). If this server cannot listen on port 443 directly, you will need a TCP load balancer or reverse proxy in front of it to forward traffic from port 443 to the server's listening port (default 8559).
- A valid public DNS record pointing to the IP where the server is running, matching the domain specified with the `-domain` flag.

## Development

### Prerequisites

- Go 1.25+

### Run locally with test certificates

Generate self-signed test certificates for localhost. Then run the server with the `-local-cert` flag to use them instead of obtaining a real certificate from Let's Encrypt.

```bash
./gen-certs.sh
```

This creates `certs/ca.crt`, `certs/server.crt`, `certs/client.crt`, and their corresponding keys.

Run tests:

```bash
go test ./...
```

Build:

```bash
go build -o entra-cba-id-generator .
```

## How Entra CBA mapping works

When a user authenticates with a certificate, Entra ID compares attributes extracted from the certificate against the `certificateUserIDs` configured on the user object in Entra. This tool generates all valid mapping strings so you can copy the correct value into the user's profile.

See the [Microsoft docs](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication-technical-deep-dive#understanding-the-username-binding-policy) for details on the username binding policy.

## License

MIT
