package inventory

import "testing"

func TestLookupCertificateForDomain_FindsValidMatchBySAN(t *testing.T) {
	cert, status := LookupCertificateForDomain([]TLSCertificate{
		{
			Path:      "/etc/letsencrypt/live/app.example.com-0001/fullchain.pem",
			Names:     []string{"app.example.com", "www.app.example.com"},
			ExpiresAt: "Jan  1 00:00:00 2030 GMT",
			Valid:     true,
		},
	}, "app.example.com")

	if status != TLSCertificateStatusValid {
		t.Fatalf("expected valid status, got %s", status)
	}
	if cert.Path == "" {
		t.Fatal("expected matching certificate")
	}
}

func TestLookupCertificateForDomain_ReturnsInvalidWhenOnlyExpiredMatchExists(t *testing.T) {
	_, status := LookupCertificateForDomain([]TLSCertificate{
		{
			Path:      "/etc/letsencrypt/live/app.example.com/fullchain.pem",
			Names:     []string{"app.example.com"},
			ExpiresAt: "Jan  1 00:00:00 2024 GMT",
			Valid:     false,
		},
	}, "app.example.com")

	if status != TLSCertificateStatusInvalid {
		t.Fatalf("expected invalid status, got %s", status)
	}
}

func TestLookupCertificateForDomain_MatchesWildcardCoverage(t *testing.T) {
	_, status := LookupCertificateForDomain([]TLSCertificate{
		{
			Path:      "/etc/letsencrypt/live/wildcard/fullchain.pem",
			Names:     []string{"*.example.com"},
			ExpiresAt: "Jan  1 00:00:00 2030 GMT",
			Valid:     true,
		},
	}, "api.example.com")

	if status != TLSCertificateStatusValid {
		t.Fatalf("expected wildcard match to be valid, got %s", status)
	}
}
