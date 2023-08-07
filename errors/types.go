package errors

import (
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
	N string
}

func (d DomainNotFound) Error() string {
	return fmt.Sprintf("domain not found: %s", d.N)
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
