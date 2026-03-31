package main_test

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"os"
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

func TestParse(t *testing.T) {
	certBytes, err := os.ReadFile("certs/LarsHIT.cer")
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}

	var sanDER []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(sanOID) {
			sanDER = ext.Value
			break
		}
	}
	if sanDER == nil {
		t.Fatal("SAN extension not found in certificate")
	}

	names, err := parseSANs(sanDER)
	if err != nil {
		t.Fatalf("parseSANs: %v", err)
	}

	if len(names) < 2 {
		t.Fatalf("expected at least 2 SAN entries, got %d", len(names))
	}

	for i, name := range names {
		desc, err := describeGeneralName(name)
		if err != nil {
			t.Errorf("entry %d: %v", i, err)
			continue
		}
		t.Logf("SAN[%d]: %s", i, desc)
	}
}
