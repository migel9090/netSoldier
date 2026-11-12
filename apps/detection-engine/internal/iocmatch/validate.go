package iocmatch

import "github.com/migel9090/netSoldier/libs/indicator"

// ValidateDomainIndicator normalizes a feed-supplied domain and rejects
// anything too broad to block safely.
//
// MatchDomain walks every parent of a queried name, so an indicator of "com"
// would match EVERY .com lookup; with auto-block at critical/90 that
// escalates to a DNS sinkhole on the entire internet. The rules used to be a
// hand-written copy of threat-intel-sync's — a character deny-list and about
// 110 hand-picked suffixes — and both copies let "*.*.*", "co.kr" or
// "s3.amazonaws.com" through. They now live in libs/indicator, shared with
// threat-intel-sync: LDH labels after IDNA mapping, and no public suffix from
// either section of the real Public Suffix List.
func ValidateDomainIndicator(value string) (string, error) {
	return indicator.Domain(value)
}
