// Package awsauth implements AWS request signing using Signed Signature Version 2,
// Signed Signature Version 3, and Signed Signature Version 4. Supports S3 and STS.
package awsauth

import (
	"net/http"
	"time"
)

// Credentials stores the information necessary to authorize with AWS and it
// is from this information that requests are signed.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SecurityToken   string `json:"Token"`
	Expiration      time.Time
	Service         string
	Region          string
}

// Sign signs a request bound for AWS. It automatically chooses the best
// authentication scheme based on the service the request is going to.
func Sign(request *http.Request, credentials ...Credentials) *http.Request {
	return Sign4(request, credentials...)
}

// Sign4 signs a request with Signed Signature Version 4.
func Sign4(request *http.Request, credentials ...Credentials) *http.Request {
	keys := chooseKeys(credentials)

	// Add the X-Amz-Security-Token header when using STS
	if keys.SecurityToken != "" {
		request.Header.Set("X-Amz-Security-Token", keys.SecurityToken)
	}

	prepareRequestV4(request)
	meta := new(metadata)
	meta.service = keys.Service
	meta.region = keys.Region

	// Task 1
	hashedCanonReq := hashedCanonicalRequestV4(request, meta)

	// Task 2
	stringToSign := stringToSignV4(request, hashedCanonReq, meta)

	// Task 3
	signingKey := signingKeyV4(keys.SecretAccessKey, meta.date, meta.region, meta.service)
	signature := signatureV4(signingKey, stringToSign)

	request.Header.Set("Authorization", buildAuthHeaderV4(signature, meta, keys))

	return request
}

// expired checks to see if the temporary credentials from an IAM role are
// within 4 minutes of expiration (The IAM documentation says that new keys
// will be provisioned 5 minutes before the old keys expire). Credentials
// that do not have an Expiration cannot expire.
func (this *Credentials) expired() bool {
	if this.Expiration.IsZero() {
		// Credentials with no expiration can't expire
		return false
	}
	expireTime := this.Expiration.Add(-4 * time.Minute)
	// if t - 4 mins is before now, true
	if expireTime.Before(time.Now()) {
		return true
	} else {
		return false
	}
}

type metadata struct {
	algorithm       string
	credentialScope string
	signedHeaders   string
	date            string
	region          string
	service         string
}

const (
	envAccessKey       = "AWS_ACCESS_KEY"
	envAccessKeyID     = "AWS_ACCESS_KEY_ID"
	envSecretKey       = "AWS_SECRET_KEY"
	envSecretAccessKey = "AWS_SECRET_ACCESS_KEY"
	envSecurityToken   = "AWS_SECURITY_TOKEN"
)
