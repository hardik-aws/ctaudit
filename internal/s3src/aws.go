package s3src

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3API is the slice of the S3 client this package uses. Declaring it here
// rather than depending on the concrete client keeps the package mockable.
type S3API interface {
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// S3Store reads CloudTrail objects from a real S3 bucket.
type S3Store struct {
	client S3API
	bucket string
}

// NewS3Store wires a store to one bucket.
func NewS3Store(client S3API, bucket string) *S3Store {
	return &S3Store{client: client, bucket: bucket}
}

// ListPage returns one ListObjectsV2 page of keys under prefix.
func (s *S3Store) ListPage(ctx context.Context, prefix, token string) ([]string, string, error) {
	in := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	}
	if token != "" {
		in.ContinuationToken = aws.String(token)
	}

	out, err := s.client.ListObjectsV2(ctx, in)
	if err != nil {
		return nil, "", fmt.Errorf("list s3://%s/%s: %w", s.bucket, prefix, err)
	}

	keys := make([]string, 0, len(out.Contents))
	for _, obj := range out.Contents {
		if obj.Key != nil {
			keys = append(keys, *obj.Key)
		}
	}

	next := ""
	if out.IsTruncated != nil && *out.IsTruncated && out.NextContinuationToken != nil {
		next = *out.NextContinuationToken
	}
	return keys, next, nil
}

// Get opens one object for reading. The caller closes the returned reader.
func (s *S3Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("get s3://%s/%s: %w", s.bucket, key, err)
	}
	return out.Body, nil
}
