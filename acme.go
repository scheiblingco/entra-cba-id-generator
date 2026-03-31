package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

const (
	acmeDir         = ".acme"
	certFile        = ".acme/cert.pem"
	keyFile         = ".acme/key.pem"
	accountKeyFile  = ".acme/account.key"
	accountJSONFile = ".acme/account.json"
	renewThreshold  = 30 * 24 * time.Hour
	checkInterval   = time.Hour
)

// acmeUser implements registration.User.
type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// loadOrCreateAccountKey loads an ECDSA account key from disk, or generates
// and saves a new one if none exists.
func loadOrCreateAccountKey() (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(accountKeyFile)
	if err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			return x509.ParseECPrivateKey(block.Bytes)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(acmeDir, 0700); err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(accountKeyFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return key, pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// certNeedsRenewal returns true if the cached certificate is missing or
// expires within the renewal threshold.
func certNeedsRenewal() bool {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return true
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	return time.Until(cert.NotAfter) < renewThreshold
}

// obtainCert uses lego with tls-alpn-01 to obtain a certificate for domain.
// challengePort must be the port the ACME CA can reach via the reverse proxy
// (i.e. the same port the main server uses). The caller must ensure the main
// server is not already bound to that port before calling this.
func obtainCert(domain, challengePort string, staging bool) error {
	if err := os.MkdirAll(acmeDir, 0700); err != nil {
		return err
	}

	accountKey, err := loadOrCreateAccountKey()
	if err != nil {
		return fmt.Errorf("account key: %w", err)
	}

	user := &acmeUser{key: accountKey}

	// Load existing account registration if available.
	if data, err := os.ReadFile(accountJSONFile); err == nil {
		var reg registration.Resource
		if json.Unmarshal(data, &reg) == nil {
			user.Registration = &reg
		}
	}

	caURL := lego.LEDirectoryProduction
	if staging {
		caURL = lego.LEDirectoryStaging
	}

	cfg := lego.NewConfig(user)
	cfg.CADirURL = caURL
	cfg.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("create lego client: %w", err)
	}

	if user.Registration == nil {
		log.Println("Registering new ACME account...")
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("register ACME account: %w", err)
		}
		user.Registration = reg
		data, _ := json.Marshal(reg)
		if err := os.WriteFile(accountJSONFile, data, 0600); err != nil {
			log.Printf("warning: could not save account registration: %v", err)
		}
	}

	if err := client.Challenge.SetTLSALPN01Provider(
		tlsalpn01.NewProviderServer("", challengePort),
	); err != nil {
		return fmt.Errorf("set tls-alpn-01 provider: %w", err)
	}

	log.Printf("Obtaining certificate for %s...", domain)
	certs, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	})
	if err != nil {
		return fmt.Errorf("obtain certificate: %w", err)
	}

	if err := os.WriteFile(certFile, certs.Certificate, 0644); err != nil {
		return err
	}
	return os.WriteFile(keyFile, certs.PrivateKey, 0600)
}

// startRenewalWorker runs a background goroutine that checks certificate
// expiry every hour. When fewer than 30 days remain it shuts down the server,
// renews the certificate, then re-execs the process so the server restarts
// with the fresh certificate.
func startRenewalWorker(server *http.Server, domain, challengePort string, staging bool) {
	go func() {
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()
		for range ticker.C {
			if !certNeedsRenewal() {
				continue
			}
			log.Println("Certificate nearing expiry, starting renewal...")
			if err := server.Shutdown(context.Background()); err != nil {
				log.Printf("server shutdown during renewal: %v", err)
			}
			if err := obtainCert(domain, challengePort, staging); err != nil {
				log.Printf("certificate renewal failed: %v — restarting with existing cert", err)
			} else {
				log.Println("Certificate renewed successfully.")
			}
			exe, err := os.Executable()
			if err != nil {
				log.Fatalf("could not resolve executable path: %v", err)
			}
			log.Println("Restarting process...")
			if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
				log.Fatalf("re-exec failed: %v", err)
			}
		}
	}()
}
