package s3src

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// fakeS3API is a scripted stand-in for the AWS SDK client, used to drive
// S3Store without any network access. It returns CommonPrefixes when the
// request carries a Delimiter, mimicking a real delimiter listing.
type fakeS3API struct {
	pages []*s3.ListObjectsV2Output
	calls []*s3.ListObjectsV2Input
}

func (f *fakeS3API) ListObjectsV2(_ context.Context, params *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	f.calls = append(f.calls, params)
	if len(f.pages) == 0 {
		return &s3.ListObjectsV2Output{}, nil
	}
	out := f.pages[0]
	f.pages = f.pages[1:]
	return out, nil
}

func (f *fakeS3API) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return nil, nil
}

func TestS3StoreListDirsPaginatesCommonPrefixes(t *testing.T) {
	api := &fakeS3API{pages: []*s3.ListObjectsV2Output{
		{
			CommonPrefixes:        []types.CommonPrefix{{Prefix: aws.String("root/b/")}},
			IsTruncated:           aws.Bool(true),
			NextContinuationToken: aws.String("tok-1"),
		},
		{
			CommonPrefixes: []types.CommonPrefix{{Prefix: aws.String("root/a/")}},
			IsTruncated:    aws.Bool(false),
		},
	}}
	store := NewS3Store(api, "bucket")

	got, err := store.ListDirs(context.Background(), "root/")
	if err != nil {
		t.Fatalf("ListDirs: %v", err)
	}
	want := []string{"root/a/", "root/b/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListDirs = %v, want %v", got, want)
	}
	if len(api.calls) != 2 {
		t.Fatalf("expected 2 ListObjectsV2 calls, got %d", len(api.calls))
	}
	for i, call := range api.calls {
		if call.Delimiter == nil || *call.Delimiter != "/" {
			t.Errorf("call %d: Delimiter = %v, want \"/\"", i, call.Delimiter)
		}
	}
	if api.calls[1].ContinuationToken == nil || *api.calls[1].ContinuationToken != "tok-1" {
		t.Errorf("second call ContinuationToken = %v, want tok-1", api.calls[1].ContinuationToken)
	}
}
