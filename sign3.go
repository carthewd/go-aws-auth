// Thanks to Michael Vierling for contributing sign3.go

package awsauth

import (
	"encoding/base64"
	"net/http"
	"time"
)

func stringToSignV3(req *http.Request) string {
	// TASK 1. http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/RESTAuthentication.html#StringToSign

	return req.Header.Get("Date") + req.Header.Get("x-amz-nonce")
}

func signatureV3(stringToSign string) string {
	// TASK 2. http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/RESTAuthentication.html#Signature

	hash := hmacSHA256([]byte(Keys.SecretAccessKey), stringToSign)
	return base64.StdEncoding.EncodeToString(hash)
}

func buildAuthHeaderV3(signature string) string {
	// TASK 3. http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/RESTAuthentication.html#AuthorizationHeader

	return "AWS3-HTTPS AWSAccessKeyId=" + Keys.AccessKeyID +
		", Algorithm=HmacSHA256" +
		", Signature=" + signature
}

func prepareRequestV3(req *http.Request) *http.Request {
	ts := timestampV3()
	necessaryDefaults := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
		"x-amz-date":   ts,
		"Date":         ts,
		"x-amz-nonce":  "",
	}

	for header, value := range necessaryDefaults {
		if req.Header.Get(header) == "" {
			req.Header.Set(header, value)
		}
	}

	if req.URL.Path == "" {
		req.URL.Path += "/"
	}

	return req
}

func timestampV3() string {
	return now().Format(timeFormatV3)
}

const timeFormatV3 = time.RFC1123
