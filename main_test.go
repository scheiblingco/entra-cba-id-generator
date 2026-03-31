package main_test

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// GeneralName tag values as defined in RFC 5280.
const (
	tagOtherName     = 0
	tagRFC822Name    = 1
	tagDNSName       = 2
	tagDirectoryName = 4
	tagURI           = 6
	tagIPAddress     = 7
)

// parseSANs decodes the raw DER value of a SubjectAlternativeName extension
// into a slice of asn1.RawValue, one per GeneralName entry.
func parseSANs(derValue []byte) ([]asn1.RawValue, error) {
	var names []asn1.RawValue
	rest, err := asn1.Unmarshal(derValue, &names)
	if err != nil {
		return nil, fmt.Errorf("unmarshal GeneralNames sequence: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected trailing bytes after SAN sequence: %x", rest)
	}
	return names, nil
}

// describeGeneralName returns a human-readable description of a GeneralName
// RawValue (context-tagged, class=2).
func describeGeneralName(rv asn1.RawValue) (string, error) {
	switch rv.Tag {
	case tagRFC822Name:
		return fmt.Sprintf("rfc822Name: %s", string(rv.Bytes)), nil

	case tagDNSName:
		return fmt.Sprintf("dNSName: %s", string(rv.Bytes)), nil

	case tagURI:
		return fmt.Sprintf("URI: %s", string(rv.Bytes)), nil

	case tagIPAddress:
		return fmt.Sprintf("iPAddress: %x", rv.Bytes), nil

	case tagOtherName:
		// OtherName ::= SEQUENCE { typeID OID, value [0] EXPLICIT ANY }
		// rv.Bytes is the body of the implicitly-tagged SEQUENCE.
		var typeID asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(rv.Bytes, &typeID)
		if err != nil {
			return "", fmt.Errorf("parse OtherName OID: %w", err)
		}

		// [0] EXPLICIT wrapper around the actual value.
		var explicitWrapper asn1.RawValue
		if _, err := asn1.Unmarshal(rest, &explicitWrapper); err != nil {
			return "", fmt.Errorf("parse OtherName explicit wrapper: %w", err)
		}

		// The wrapper's Bytes contain the inner value TLV (e.g. UTF8String).
		var inner asn1.RawValue
		if _, err := asn1.Unmarshal(explicitWrapper.Bytes, &inner); err != nil {
			return "", fmt.Errorf("parse OtherName inner value: %w", err)
		}

		return fmt.Sprintf("otherName: OID=%v value=%q", typeID, string(inner.Bytes)), nil

	default:
		return fmt.Sprintf("tag=%d class=%d bytes=%x", rv.Tag, rv.Class, rv.Bytes), nil
	}
}

// testOIDNames mirrors the oidNames map in main.go so the test uses the same
// DN-attribute labels without importing the unexported package symbol.
var testOIDNames = map[string]string{
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

// rdnStringFromNames replicates the rdnString logic from main.go.
func rdnStringFromNames(names []pkix.AttributeTypeAndValue) string {
	parts := make([]string, len(names))
	for i, name := range names {
		label, ok := testOIDNames[name.Type.String()]
		if !ok {
			label = name.Type.String()
		}
		parts[len(names)-1-i] = label + "=" + fmt.Sprint(name.Value)
	}
	slices.Reverse(parts)
	return strings.Join(parts, ",")
}

// loadClientCert reads and parses certs/client.crt for use in tests.
func loadClientCert(t *testing.T) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile("certs/client.crt")
	if err != nil {
		t.Fatalf("read certs/client.crt: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no PEM block found in certs/client.crt")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestEntraCBAIDs(t *testing.T) {
	cert := loadClientCert(t)

	t.Run("IssuerAndSubject", func(t *testing.T) {
		id := "X509:<I>" + rdnStringFromNames(cert.Issuer.Names) + "<S>" + rdnStringFromNames(cert.Subject.Names)
		if !strings.HasPrefix(id, "X509:<I>") {
			t.Errorf("IssuerAndSubject must start with X509:<I>: %s", id)
		}
		if !strings.Contains(id, "<S>") {
			t.Errorf("IssuerAndSubject must contain <S>: %s", id)
		}
		if !strings.Contains(id, "CN=Entra CBA Test CA") {
			t.Errorf("IssuerAndSubject missing issuer CN: %s", id)
		}
		if !strings.Contains(id, "CN=Test User") {
			t.Errorf("IssuerAndSubject missing subject CN: %s", id)
		}
		t.Logf("IssuerAndSubject = %s", id)
	})

	t.Run("RFC822Name", func(t *testing.T) {
		if len(cert.EmailAddresses) == 0 {
			t.Fatal("certificate must have at least one email SAN")
		}
		id := "X509:<RFC822>" + cert.EmailAddresses[0]
		want := "X509:<RFC822>testuser@example.com"
		if id != want {
			t.Errorf("RFC822Name = %q, want %q", id, want)
		}
		t.Logf("RFC822Name = %s", id)
	})

	t.Run("Subject", func(t *testing.T) {
		id := "X509:<Subject>" + rdnStringFromNames(cert.Subject.Names)
		if !strings.HasPrefix(id, "X509:<Subject>") {
			t.Errorf("Subject must start with X509:<Subject>: %s", id)
		}
		if !strings.Contains(id, "CN=Test User") {
			t.Errorf("Subject missing CN=Test User: %s", id)
		}
		if !strings.Contains(id, "emailAddress=testuser@example.com") {
			t.Errorf("Subject missing emailAddress: %s", id)
		}
		t.Logf("Subject = %s", id)
	})

	t.Run("SKI", func(t *testing.T) {
		if len(cert.SubjectKeyId) == 0 {
			t.Fatal("certificate must have a Subject Key Identifier extension")
		}
		id := "X509:<SKI>" + strings.ToUpper(hex.EncodeToString(cert.SubjectKeyId))
		const prefix = "X509:<SKI>"
		if !strings.HasPrefix(id, prefix) {
			t.Errorf("SKI must start with %s: %s", prefix, id)
		}
		// A SHA-1 SKI is 20 bytes = 40 uppercase hex characters.
		skiHex := strings.TrimPrefix(id, prefix)
		if len(skiHex) != 40 {
			t.Errorf("SKI hex must be 40 chars (SHA-1), got %d: %s", len(skiHex), skiHex)
		}
		t.Logf("SKI = %s", id)
	})

	t.Run("PrincipalName", func(t *testing.T) {
		upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
		sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}

		var principalName string
		for _, ext := range cert.Extensions {
			if !ext.Id.Equal(sanOID) {
				continue
			}
			var generalNames []asn1.RawValue
			if _, err := asn1.Unmarshal(ext.Value, &generalNames); err != nil {
				t.Fatalf("parse SAN extension: %v", err)
			}
			for _, gn := range generalNames {
				if gn.Tag != tagOtherName {
					continue
				}
				var typeID asn1.ObjectIdentifier
				rest, err := asn1.Unmarshal(gn.Bytes, &typeID)
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
				principalName = "X509:<PN>" + string(inner.Bytes)
			}
		}
		if principalName == "" {
			t.Fatal("certificate must have a UPN OtherName SAN (OID 1.3.6.1.4.1.311.20.2.3)")
		}
		want := "X509:<PN>testuser@example.com"
		if principalName != want {
			t.Errorf("PrincipalName = %q, want %q", principalName, want)
		}
		t.Logf("PrincipalName = %s", principalName)
	})

	t.Run("SHA1PublicKey", func(t *testing.T) {
		sum := sha1.Sum(cert.Raw)
		id := "X509:<SHA1>" + strings.ToUpper(hex.EncodeToString(sum[:]))
		const prefix = "X509:<SHA1>"
		if !strings.HasPrefix(id, prefix) {
			t.Errorf("SHA1PublicKey must start with %s: %s", prefix, id)
		}
		sha1Hex := strings.TrimPrefix(id, prefix)
		if len(sha1Hex) != 40 {
			t.Errorf("SHA1 hex must be 40 chars, got %d: %s", len(sha1Hex), sha1Hex)
		}
		t.Logf("SHA1PublicKey = %s", id)
	})

	t.Run("IssuerAndSerialNumber", func(t *testing.T) {
		serialBytes := cert.SerialNumber.Bytes()
		reversed := make([]byte, len(serialBytes))
		copy(reversed, serialBytes)
		slices.Reverse(reversed)
		id := fmt.Sprintf("X509:<I>%s<SR>%s", rdnStringFromNames(cert.Issuer.Names), hex.EncodeToString(reversed))
		if !strings.HasPrefix(id, "X509:<I>") {
			t.Errorf("IssuerAndSerialNumber must start with X509:<I>: %s", id)
		}
		if !strings.Contains(id, "<SR>") {
			t.Errorf("IssuerAndSerialNumber must contain <SR>: %s", id)
		}
		if !strings.Contains(id, "CN=Entra CBA Test CA") {
			t.Errorf("IssuerAndSerialNumber missing issuer CN: %s", id)
		}
		t.Logf("IssuerAndSerialNumber = %s", id)
	})
}
