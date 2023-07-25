package errors

import "fmt"

type NetworkIssue struct {
	Reason error
}

func (n NetworkIssue) Error() string {
	return fmt.Sprintf("NetworkIssue: %s", n.Reason.Error())
}

type DomainNotFound struct {
	N string
}

func (d DomainNotFound) Error() string {
	return fmt.Sprintf("[%s] domain not found", d.N)
}

type ConnectionTimeout struct{}

func (ct ConnectionTimeout) Error() string {
	return "connection timeout"
}
