package errors

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type NetworkIssue struct {
	Reason error
}

func (n NetworkIssue) Error() string {
	return fmt.Sprintf("network issue: %s", n.Reason.Error())
}

type DomainNotFound struct {
	N   string
	Err error
}

func (d DomainNotFound) Wrap(err error) DomainNotFound {
	if !errors.Is(err, d) {
		d.Err = err
	}
	return d
}

func (d DomainNotFound) Unwrap() error {
	return d.Err
}

func (d DomainNotFound) Error() string {
	return fmt.Sprintf("domain not found: %s, cause: %s", d.N, d.Err.Error())
}

type ConnectionTimeout struct{}

func (ct ConnectionTimeout) Error() string {
	return "connection timeout"
}

type AuthorityIsNotNS struct {
	Ns dns.RR
}

func (a AuthorityIsNotNS) Error() string {
	return fmt.Sprintf("authority record is not an NS:\n\t%s", a.Ns.String())
}

type NoARecordsForNS struct {
	Ns    dns.RR
	Extra []dns.RR
}

func (n NoARecordsForNS) Error() string {
	return fmt.Sprintf("no A record in extra for the following NS: %s\n\t%s", n.Ns.Header().Name, n.listExtra())
}

func (n NoARecordsForNS) listExtra() string {
	response := []string{}
	for _, extra := range n.Extra {
		response = append(response, extra.String())
	}
	return strings.Join(response, "\n")
}

type DNSConnectionError struct {
	Cause error
}

type DNSDialErr DNSConnectionError

func (d DNSDialErr) Error() string {
	return fmt.Sprintf("error dialing DNS: %s", d.Cause.Error())
}

func (d DNSDialErr) Is(another error) bool {
	return another == DNSDialErr{}
}

type DNSWriteErr DNSConnectionError

func (d DNSWriteErr) Error() string {
	return fmt.Sprintf("error writing DNS request: %s", d.Cause.Error())
}

type DNSReadErr DNSConnectionError

func (d DNSReadErr) Error() string {
	return fmt.Sprintf("error reading DNS response: %s", d.Cause.Error())
}

type DNSResponseNilWithoutError struct {
	N string
}

func (d DNSResponseNilWithoutError) Error() string {
	return fmt.Sprintf("%s: DNS response is nil without any error, this should not happen!", d.N)
}
