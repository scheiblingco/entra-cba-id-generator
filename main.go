package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/scheiblingco/gofn/typetools"
)

type CertInfo struct {
	CommonName      string
	Issuer          string
	SerialNumber    string
	NotBefore       string
	NotAfter        string
	DNSNames        []string
	EmailAddresses  []string
	IPAddresses     []string
	URIs            []string
	Fingerprint     string
	IsExpired       bool
	DaysUntilExpiry int64

	IssuerAndSubject      string
	RFC822Name            string
	Subject               string
	SKI                   string
	PrincipalName         string
	SHA1PublicKey         string
	IssuerAndSerialNumber string
}

var pageTemplate = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Client Certificate Info</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f0f2f5;
      color: #1a1a2e;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem;
    }

    .card {
      background: #ffffff;
      border-radius: 12px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.10);
      width: 100%;
      max-width: 720px;
      overflow: hidden;
    }

    .card-header {
      background: #0f3460;
      color: #ffffff;
      padding: 1.5rem 2rem;
      display: flex;
      align-items: center;
      gap: 1rem;
    }

    .card-header .icon {
      font-size: 2rem;
      line-height: 1;
    }

    .card-header h1 {
      font-size: 1.25rem;
      font-weight: 600;
      letter-spacing: 0.01em;
    }

    .card-header .cn {
      font-size: 0.875rem;
      opacity: 0.75;
      margin-top: 0.2rem;
    }

    .status-bar {
      padding: 0.6rem 2rem;
      font-size: 0.8rem;
      font-weight: 600;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }

    .status-bar.valid   { background: #e6f4ea; color: #1e7e34; }
    .status-bar.expired { background: #fdecea; color: #c0392b; }

    .card-body {
      padding: 1.75rem 2rem;
    }

    .section-title {
      font-size: 0.7rem;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: #888;
      margin-bottom: 0.75rem;
      margin-top: 1.5rem;
    }

    .section-title:first-child { margin-top: 0; }

    table {
      width: 100%;
      border-collapse: collapse;
    }

    tr { border-bottom: 1px solid #f0f0f0; }
    tr:last-child { border-bottom: none; }

    td {
      padding: 0.55rem 0;
      vertical-align: top;
      font-size: 0.875rem;
      line-height: 1.5;
    }

    td.label {
      color: #666;
      width: 38%;
      padding-right: 1rem;
      white-space: nowrap;
    }

    td.value {
      color: #1a1a2e;
      word-break: break-all;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 0.8125rem;
    }

    .tag-list { display: flex; flex-wrap: wrap; gap: 0.4rem; }

    .tag {
      background: #eef2ff;
      color: #3730a3;
      border-radius: 4px;
      padding: 0.15rem 0.5rem;
      font-size: 0.775rem;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    }

    .tag.email { background: #fef3c7; color: #92400e; }
    .tag.ip    { background: #ecfdf5; color: #065f46; }
    .tag.uri   { background: #fdf4ff; color: #7e22ce; }

    .fingerprint {
      font-size: 0.75rem;
      word-spacing: 0.1em;
    }

    .card-footer {
      background: #f8f9fa;
      border-top: 1px solid #eee;
      padding: 0.9rem 2rem;
      font-size: 0.75rem;
      color: #aaa;
      text-align: right;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="card-header">
      <div class="icon">🔐</div>
      <div>
        <h1>Entra CertificateUserID Generator</h1>
        <div class="cn">{{.CommonName}}</div>
      </div>
    </div>

    {{if .IsExpired}}
    <div class="status-bar expired">&#x26A0; Certificate expired</div>
    {{else}}
    <div class="status-bar valid">&#x2713; Valid &mdash; {{.DaysUntilExpiry}} days remaining</div>
    {{end}}

    <div class="card-body">

      <div class="section-title">Identity</div>
      <table>
        <tr>
          <td class="label">Common Name</td>
          <td class="value">{{.CommonName}}</td>
        </tr>
        <tr>
          <td class="label">Subject</td>
          <td class="value">{{.Subject}}</td>
        </tr>
        <tr>
          <td class="label">Issuer</td>
          <td class="value">{{.Issuer}}</td>
        </tr>
        <tr>
          <td class="label">Serial Number</td>
          <td class="value">{{.SerialNumber}}</td>
        </tr>
      </table>

      <div class="section-title">Validity</div>
      <table>
        <tr>
          <td class="label">Not Before</td>
          <td class="value">{{.NotBefore}}</td>
        </tr>
        <tr>
          <td class="label">Not After</td>
          <td class="value">{{.NotAfter}}</td>
        </tr>
      </table>

      {{if or .DNSNames .EmailAddresses .IPAddresses .URIs}}
      <div class="section-title">Subject Alternative Names</div>
      <table>
        {{if .DNSNames}}
        <tr>
          <td class="label">DNS Names</td>
          <td class="value">
            <div class="tag-list">
              {{range .DNSNames}}<span class="tag">{{.}}</span>{{end}}
            </div>
          </td>
        </tr>
        {{end}}
        {{if .EmailAddresses}}
        <tr>
          <td class="label">Email Addresses</td>
          <td class="value">
            <div class="tag-list">
              {{range .EmailAddresses}}<span class="tag email">{{.}}</span>{{end}}
            </div>
          </td>
        </tr>
        {{end}}
        {{if .IPAddresses}}
        <tr>
          <td class="label">IP Addresses</td>
          <td class="value">
            <div class="tag-list">
              {{range .IPAddresses}}<span class="tag ip">{{.}}</span>{{end}}
            </div>
          </td>
        </tr>
        {{end}}
        {{if .URIs}}
        <tr>
          <td class="label">URIs</td>
          <td class="value">
            <div class="tag-list">
              {{range .URIs}}<span class="tag uri">{{.}}</span>{{end}}
            </div>
          </td>
        </tr>
        {{end}}
      </table>
      {{end}}

      <div class="section-title">Entra CertificateUserIDs</div>
      <table>
        <tr>
          <td class="label">IssuerAndSubject</td>
          <td class="value fingerprint">{{.IssuerAndSubject}}</td>
        </tr>
        <tr>
          <td class="label">RFC822Name</td>
          <td class="value fingerprint">{{.RFC822Name}}</td>
        </tr>
        <tr>
          <td class="label">Subject</td>
          <td class="value fingerprint">{{.Subject}}</td>
        </tr>
        <tr>
          <td class="label">SKI</td>
          <td class="value fingerprint">{{.SKI}}</td>
        </tr>
        <tr>
          <td class="label">PrincipalName</td>
          <td class="value fingerprint">{{.PrincipalName}}</td>
        </tr>
        <tr>
          <td class="label">SHA1PublicKey</td>
          <td class="value fingerprint">{{.SHA1PublicKey}}</td>
        </tr>
        <tr>
          <td class="label">IssuerAndSerialNumber</td>
          <td class="value fingerprint">{{.IssuerAndSerialNumber}}</td>
        </tr>
      </table>

    </div>
    <div class="card-footer">entra-cba-id-generator &mdash; mTLS certificate viewer</div>
  </div>
</body>
</html>
`))

// oidNames maps common X.520 and LDAP OIDs to their short attribute names.
// Go's pkix package only covers 9 OIDs internally; this covers the full set
// typically found in AD/Entra certificates (including SN, GN, etc.).
var oidNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "SERIALNUMBER",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "STREET",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "T",
	"2.5.4.17":                   "POSTALCODE",
	"2.5.4.42":                   "GN",
	"2.5.4.43":                   "initials",
	"2.5.4.44":                   "generationQualifier",
	"2.5.4.46":                   "dnQualifier",
	"2.5.4.65":                   "pseudonym",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1":  "UID",
}

// rdnString formats DN attributes as a comma-separated string in reversed
// order (least significant first), using short attribute names where known.
func rdnString(names []pkix.AttributeTypeAndValue) string {
	parts := make([]string, len(names))
	for i, name := range names {
		label, ok := oidNames[name.Type.String()]
		if !ok {
			label = name.Type.String()
		}
		parts[len(names)-1-i] = label + "=" + fmt.Sprint(name.Value)
	}

	slices.Reverse(parts)

	return strings.Join(parts, ",")
}

func certHandler(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "No client certificate presented", http.StatusUnauthorized)
		return
	}

	cert := r.TLS.PeerCertificates[0]

	// SHA-256 fingerprint formatted as colon-separated hex pairs
	raw := sha256.Sum256(cert.Raw)
	hexStr := hex.EncodeToString(raw[:])
	pairs := make([]string, len(hexStr)/2)
	for i := range pairs {
		pairs[i] = hexStr[i*2 : i*2+2]
	}

	now := time.Now()
	daysUntil := int64(cert.NotAfter.Sub(now).Hours() / 24)

	// Collect IP addresses as strings
	ips := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ips[i] = ip.String()
	}

	// Collect URIs as strings
	uris := make([]string, len(cert.URIs))
	for i, u := range cert.URIs {
		uris[i] = u.String()
	}

	info := CertInfo{
		CommonName:      cert.Subject.CommonName,
		Issuer:          cert.Issuer.String(),
		SerialNumber:    cert.SerialNumber.String(),
		NotBefore:       cert.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC"),
		NotAfter:        cert.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC"),
		DNSNames:        cert.DNSNames,
		EmailAddresses:  cert.EmailAddresses,
		IPAddresses:     ips,
		URIs:            uris,
		Fingerprint:     strings.Join(pairs, ":"),
		IsExpired:       now.After(cert.NotAfter),
		DaysUntilExpiry: daysUntil,
	}

	info.IssuerAndSubject = "X509:<I>" + rdnString(cert.Issuer.Names) + "<S>" + rdnString(cert.Subject.Names)

	if len(cert.EmailAddresses) > 0 {
		info.RFC822Name = "X509:<RFC822>" + cert.EmailAddresses[0]
	}

	info.Subject = "X509:<Subject>" + rdnString(cert.Subject.Names)

	if len(cert.SubjectKeyId) > 0 {
		info.SKI = "X509:<SKI>" + strings.ToUpper(hex.EncodeToString(cert.SubjectKeyId))
	}

	// Extract UPN from the OtherName SAN entry (OID 1.3.6.1.4.1.311.20.2.3).
	upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(sanOID) {
			continue
		}
		var names []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &names); err != nil {
			log.Printf("error parsing SAN extension: %v", err)
			break
		}
		for _, name := range names {
			if name.Tag != 0 { // 0 = otherName
				continue
			}
			var typeID asn1.ObjectIdentifier
			rest, err := asn1.Unmarshal(name.Bytes, &typeID)
			if err != nil || !typeID.Equal(upnOID) {
				continue
			}
			var wrapper asn1.RawValue
			if _, err := asn1.Unmarshal(rest, &wrapper); err != nil {
				continue
			}
			var inner asn1.RawValue
			if _, err := asn1.Unmarshal(wrapper.Bytes, &inner); err != nil {
				continue
			}
			info.PrincipalName = "X509:<PN>" + string(inner.Bytes)
			break
		}
		break
	}

	sha1pk := sha1.Sum(cert.Raw)
	info.SHA1PublicKey = "X509:<SHA1>" + strings.ToUpper(hex.EncodeToString(sha1pk[:]))

	serialnumber := cert.SerialNumber.Bytes()

	reversedSN := serialnumber
	slices.Reverse(reversedSN)

	info.IssuerAndSerialNumber = fmt.Sprintf("X509:<I>%s<SR>%s", rdnString(cert.Issuer.Names), hex.EncodeToString(reversedSN))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.Execute(w, info); err != nil {
		log.Printf("template error: %v", err)
	}
}

func main() {
	domain := flag.String("domain", "localhost", "domain to obtain a certificate for")
	staging := flag.Bool("staging", false, "use Let's Encrypt staging environment")
	localCert := flag.Bool("local-cert", false, "use a local self-signed certificate instead of obtaining one from ACME (for testing)")
	challengePort := flag.Int("port", 8559, "port to listen on for HTTPS connections")

	flag.Parse()

	if *challengePort != 443 && !*localCert {
		log.Printf("Warning: Using non-standard port %d. You will need a TCP load balancer in front of this server to handle ACME TLS-ALPN-01 challenges on port 443 and forward them to this port.", *challengePort)
	}

	if certNeedsRenewal() && !*localCert {
		log.Println("No valid certificate found, obtaining one now...")
		if err := obtainCert(*domain, typetools.EnsureString(challengePort), *staging); err != nil {
			log.Fatalf("initial certificate obtain failed: %v", err)
		}
		log.Println("Certificate obtained successfully.")
	}

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
		MinVersion: tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:      ":" + typetools.EnsureString(challengePort),
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(certHandler),
	}

	if !*localCert {
		startRenewalWorker(server, *domain, typetools.EnsureString(challengePort), *staging)
	}

	log.Printf("Listening on https://localhost:%s (mTLS required)", typetools.EnsureString(challengePort))

	if *localCert {
		log.Println("Using local self-signed certificate for testing.")
		if err := server.ListenAndServeTLS("certs/server.crt", "certs/server.key"); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
		return
	}
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}
