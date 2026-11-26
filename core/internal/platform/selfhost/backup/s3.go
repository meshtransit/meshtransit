package backup

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// maxCredentialsFile bounds the S3 credential file.
const maxCredentialsFile = 4096

// S3 is an S3-compatible bucket backups are copied to: one signed PUT per
// file (a one-server backup stays far below the 5 GB PUT limit). The
// credential needs only PutObject; retention is the bucket's lifecycle
// rule, and versioning or Object Lock keeps a compromised server from
// replacing what is there.
type S3 struct {
	Endpoint string // https://host[:port]
	Region   string
	Bucket   string
	Prefix   string // object key prefix; the Deployment ID follows it
	// CredentialsFile holds ACCESS_KEY_ID=… and SECRET_ACCESS_KEY=… lines.
	CredentialsFile string
	Client          *http.Client
}

// ReadS3Credentials reads the credential file: a regular file, never
// through a link, at most 4 KiB, with two KEY=value lines.
func ReadS3Credentials(location string) (aws.Credentials, error) {
	file, err := os.OpenFile(location, os.O_RDONLY|noFollow, 0) // #nosec G304 -- the operator's file.
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("s3 credentials: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxCredentialsFile {
		return aws.Credentials{}, fmt.Errorf("%w: s3 credentials must be a regular file of at most 4 KiB", ErrInvalid)
	}
	values := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(file, maxCredentialsFile))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return aws.Credentials{}, fmt.Errorf("%w: s3 credentials: a line is not KEY=value", ErrInvalid)
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return aws.Credentials{}, fmt.Errorf("s3 credentials: %w", err)
	}
	credentials := aws.Credentials{AccessKeyID: values["ACCESS_KEY_ID"], SecretAccessKey: values["SECRET_ACCESS_KEY"]}
	if credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" || len(values) != 2 {
		return aws.Credentials{}, fmt.Errorf("%w: s3 credentials need exactly ACCESS_KEY_ID and SECRET_ACCESS_KEY",
			ErrInvalid)
	}
	return credentials, nil
}

// ObjectURL is where a backup file goes (path style: works with every
// S3-compatible store).
func (target S3) ObjectURL(deploymentID, name string) (*url.URL, error) {
	endpoint, err := url.Parse(target.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.Path != "" && endpoint.Path != "/" ||
		endpoint.RawQuery != "" || endpoint.User != nil {
		return nil, fmt.Errorf("%w: s3 endpoint must be https://host[:port]", ErrInvalid)
	}
	key := path.Join(strings.Trim(target.Prefix, "/"), strings.ToLower(deploymentID), name)
	endpoint.Path = "/" + target.Bucket + "/" + key
	return endpoint, nil
}

// Upload PUTs one finished backup file. payloadSHA256 is the file's hex
// SHA-256 (the store computed it while writing): S3 checks the body
// against it.
func (target S3) Upload(ctx context.Context, deploymentID, location, payloadSHA256 string) error {
	credentials, err := ReadS3Credentials(target.CredentialsFile)
	if err != nil {
		return err
	}
	object, err := target.ObjectURL(deploymentID, path.Base(location))
	if err != nil {
		return err
	}
	file, err := os.OpenFile(location, os.O_RDONLY|noFollow, 0) // #nosec G304 -- the backup just written.
	if err != nil {
		return fmt.Errorf("s3 upload: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("s3 upload: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, object.String(), file)
	if err != nil {
		return fmt.Errorf("s3 upload: %w", err)
	}
	request.ContentLength = info.Size()
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Amz-Content-Sha256", payloadSHA256)
	if err := v4.NewSigner().SignHTTP(ctx, credentials, request, payloadSHA256, "s3", target.Region,
		time.Now().UTC()); err != nil {
		return fmt.Errorf("s3 sign: %w", err)
	}
	client := target.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Hour}
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("s3 upload: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode/100 != 2 {
		// The body may echo the request; only the status is reported.
		return fmt.Errorf("s3 upload: status %d", response.StatusCode)
	}
	return nil
}
