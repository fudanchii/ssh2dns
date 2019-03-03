package request

// lookupRequest holds information for each request,
// including source address, payload data and
// DNS server being used.
type LookupRequest struct {
	CliConn    *net.UDPConn
	Data       []byte
	DNS        string
	SourceAddr *net.UDPAddr
}
