package tpm

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

const (
	DefaultDownloadTimeout = 10 * time.Millisecond
	// JSON response for https://ekop.intel.com/ekcertservice/WVEG2rRwkQ7m3RpXlUphgo6Y2HLxl18h6ZZkkOAdnBE%3D; also see https://github.com/tpm2-software/tpm2-tools/blob/master/test/integration/tests/getekcertificate.sh
	intelEKMockResponse = `{"pubhash":"WVEG2rRwkQ7m3RpXlUphgo6Y2HLxl18h6ZZkkOAdnBE%3D","certificate":"MIIEnDCCBEOgAwIBAgIEfT80-DAKBggqhkjOPQQDAjCBlTELMAkGA1UEBgwCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xLzAtBgNVBAsMJlRQTSBFSyBpbnRlcm1lZGlhdGUgZm9yIFNQVEhfRVBJRF9QUk9EMRYwFAYDVQQDDA13d3cuaW50ZWwuY29tMB4XDTE1MDUyMjAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMMg4vJEqGAarPPgHSbGZSSZNVYt4doZfp5_B2xGlhPPtlPpjsLDhvwdEz8sjGzDOLcy8LIIvYOKh3o-W7w-HUCE6DXHyJBqHAW00tMP2-vB262VD6axZb1LaoZGAxRhZMDE9Z1IkBHvH5KN7qbpAGHz03XlZGJzFR72IiUgmL4aSrAdwKEiJ8YJ_azrEVr0CNRpOm9JkZd0aVsMErwYof9xIKczey-18ZUdi7fwlNW1VMEclSOzByn-ZHh9ChO55jBIjatN_YZjSlJw7HL8xaRNxnmo8yk43YGX4p2ug59bTKD13ifJUiwjxU4cLOV4WVJRGL1EcLGBgO73iuQme80CAwEAAaOCAkgwggJEMA8GA1UdEwEB_wQFMAMBAQAwDgYDVR0PAQH_BAQDAgAgMBAGA1UdJQQJMAcGBWeBBQgBMCQGA1UdCQEBAAQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAWcwUAYDVR0RAQH_BEYwRKRCMEAxFjAUBgVngQUCAQwLaWQ6NDk0RTU0NDMxDjAMBgVngQUCAgwDU1BUMRYwFAYFZ4EFAgMMC2lkOjAwMDIwMDAwMB8GA1UdIwQYMBaAFF5zyJqj6QKycrnwdB99hzDj7HJKMFgGA1UdHwRRME8wTaBLoEmGR2h0dHA6Ly91cGdyYWRlcy5pbnRlbC5jb20vY29udGVudC9DUkwvZWtjZXJ0L1NQVEhFUElEUFJPRF9FS19EZXZpY2UuY3JsMHAGCCsGAQUFBwEBBGQwYjBgBggrBgEFBQcwAoZUaHR0cDovL3VwZ3JhZGVzLmludGVsLmNvbS9jb250ZW50L0NSTC9la2NlcnQvU1BUSEVQSURQUk9EX0VLX1BsYXRmb3JtX1B1YmxpY19LZXkuY2VyMIGpBgNVHSAEgaEwgZ4wgZsGCiqGSIb4TQEFAgEwgYwwUgYIKwYBBQUHAgEWRmh0dHA6Ly91cGdyYWRlcy5pbnRlbC5jb20vY29udGVudC9DUkwvZWtjZXJ0L0VLY2VydFBvbGljeVN0YXRlbWVudC5wZGYwNgYIKwYBBQUHAgIwKgwoVENQQSBUcnVzdGVkIFBsYXRmb3JtIE1vZHVsZSBFbmRvcnNlbWVudDAKBggqhkjOPQQDAgNHADBEAiBrQr0ckEoWsrx0971bppP6N8PTb4U6z_hIqpS6o150xAIgNxZNXq7bCqU1b4hGdiSBauowiOVFcaaiTm1p99H_k1Q%3D"}`

	// base64 encoded response for https://ftpm.amd.com/pki/aia/264D39A23CEB5D5B49D610044EEBD121
	amdEKRootMockResponseBase64 = `MIIEiDCCA3CgAwIBAgIQJk05ojzrXVtJ1hAETuvRITANBgkqhkiG9w0BAQsFADB2MRQwEgYDVQQLEwtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxEjAQBgNVBAcTCVN1bm55dmFsZTELMAkGA1UECBMCQ0ExHzAdBgNVBAoTFkFkdmFuY2VkIE1pY3JvIERldmljZXMxDzANBgNVBAMTBkFNRFRQTTAeFw0xNDEwMjMxNDM0MzJaFw0zOTEwMjMxNDM0MzJaMHYxFDASBgNVBAsTC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzESMBAGA1UEBxMJU3Vubnl2YWxlMQswCQYDVQQIEwJDQTEfMB0GA1UEChMWQWR2YW5jZWQgTWljcm8gRGV2aWNlczEPMA0GA1UEAxMGQU1EVFBNMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAssnOAYu5nRflQk0bVtsTFcLSAMx9odZ4Ey3n6/MA6FD7DECIE70RGZgaRIID0eb+dyX3znMrp1TS+lD+GJSw7yDJrKeU4it8cMLqFrqGm4SEx/X5GBa11sTmL4i60pJ5nDo2T69OiJ+iqYzgBfYJLqHQaeSRN6bBYyn3w1H4JNzPDNvqKHvkPfYewHjUAFJAI1dShYO8REnNCB8eeolj375nymfAAZzgA8v7zmFX/1tVLCy7Mm6n7zndT452TB1mek9LC5LkwlnyABwaN2Q8LV4NWpIAzTgr55xbU5VvgcIpw+/qcbYHmqL6ZzCSeE1gRKQXlsybK+W4phCtQfMgHQIDAQABo4IBEDCCAQwwDgYDVR0PAQH/BAQDAgEGMCMGCSsGAQQBgjcVKwQWBBRXjFRfeWlRQhIhpKV4rNtfaC+JyDAdBgNVHQ4EFgQUV4xUX3lpUUISIaSleKzbX2gvicgwDwYDVR0TAQH/BAUwAwEB/zA4BggrBgEFBQcBAQQsMCowKAYIKwYBBQUHMAGGHGh0dHA6Ly9mdHBtLmFtZC5jb20vcGtpL29jc3AwLAYDVR0fBCUwIzAhoB+gHYYbaHR0cDovL2Z0cG0uYW1kLmNvbS9wa2kvY3JsMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRwczovL2Z0cG0uYW1kLmNvbS9wa2kvY3BzMA0GCSqGSIb3DQEBCwUAA4IBAQCWB9yAoYYIt5HRY/OqJ5LUacP6rNmsMfPUDTcahXB3iQmY8HpUoGB23lhxbq+kz3vIiGAcUdKHlpB/epXyhABGTcJrNPMfx9akLqhI7WnMCPBbHDDDzKjjMB3Vm65PFbyuqbLujN/sN6kNtc4hL5r5Pr6Mze5H9WXBo2F2Oy+7+9jWMkxNrmUhoUUrF/6YsajTGPeq7r+i6q84W2nJdd+BoQQv4sk5GeuN2j2u4k1a8DkRPsVPc2I9QTtbzekchTK1GCXWki3DKGkZUEuaoaa60Kgw55Q5rt1eK7HKEG5npmR8aEod7BDLWy4CMTNAWR5iabCW/KX28JbJL6Phau9j`
)

// mockClient is a mock implementation of httpClient for testing purposes.
type MockClient struct {
	doFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockClient) Do(req *http.Request) (*http.Response, error) {
	if m.doFunc != nil {
		return m.doFunc(req)
	}
	return nil, errors.New("mocked doFunc not set")
}

func NewDefaultDowloaderMockClient(t *testing.T) *MockClient {
	return NewDownloaderMockClient(t, DefaultDownloadTimeout)
}

func NewDownloaderMockClient(t *testing.T, delay time.Duration) *MockClient {
	return NewDownloaderWithCRLMockClient(t, delay, nil, nil)
}

func NewDownloaderWithCRLMockClient(t *testing.T, delay time.Duration, intelEKCRLMockResponse, intelEKCAMockResponse []byte) *MockClient {
	return &MockClient{
		doFunc: func(req *http.Request) (*http.Response, error) {
			select {
			case <-time.After(delay):
				switch {
				case req.URL.String() == "http://upgrades.intel.com/content/CRL/ekcert/SPTHEPIDPROD_EK_Device.crl":
					r := io.NopCloser(bytes.NewReader(intelEKCRLMockResponse))
					return &http.Response{
						StatusCode: 200,
						Body:       r,
					}, nil
				case req.URL.String() == "http://upgrades.intel.com/content/CRL/ekcert/SPTHEPIDPROD_EK_Platform_Public_Key.cer":
					r := io.NopCloser(bytes.NewReader(intelEKCAMockResponse))
					return &http.Response{
						StatusCode: 200,
						Body:       r,
					}, nil
				case req.URL.String() == "https://ekop.intel.com/ekcertservice/WVEG2rRwkQ7m3RpXlUphgo6Y2HLxl18h6ZZkkOAdnBE%3D":
					r := io.NopCloser(bytes.NewReader([]byte(intelEKMockResponse)))
					return &http.Response{
						StatusCode: 200,
						Body:       r,
					}, nil
				case req.URL.String() == "https://ftpm.amd.com/pki/aia/264D39A23CEB5D5B49D610044EEBD121":
					b, err := base64.StdEncoding.DecodeString(amdEKRootMockResponseBase64)
					if err != nil {
						t.Fatalf("failed to decode AmdEKRootMockResponseBase64: %v", err)
					}
					r := io.NopCloser(bytes.NewReader(b))
					return &http.Response{
						StatusCode: 200,
						Body:       r,
					}, nil
				case req.URL.String() == "http://pki/signer.cer":
					b, err := base64.StdEncoding.DecodeString(amdEKRootMockResponseBase64)
					if err != nil {
						t.Fatalf("failed to decode AmdEKRootMockResponseBase64: %v", err)
					}
					r := io.NopCloser(bytes.NewReader(b))
					return &http.Response{
						StatusCode: 200,
						Body:       r,
					}, nil
				}
				return nil, errors.New("unexpected URL")
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		},
	}
}
