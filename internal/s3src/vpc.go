package s3src

import "strings"

// VPCHivePrefix returns where a flow log created with Hive-compatible S3
// prefixes writes for one account and region. ctaudit does not read that
// layout; the engine lists this prefix only to explain an empty scan. The
// layout has no Organizations segment, so OrgID is not used.
func (s Scope) VPCHivePrefix(account, region string) string {
	var b strings.Builder
	if base := strings.Trim(s.BasePrefix, "/"); base != "" {
		b.WriteString(base)
		b.WriteString("/")
	}
	b.WriteString("AWSLogs/aws-account-id=")
	b.WriteString(account)
	b.WriteString("/aws-service=")
	b.WriteString(ServiceVPC)
	b.WriteString("/aws-region=")
	b.WriteString(region)
	b.WriteString("/")
	return b.String()
}
