// Package flowlog decodes VPC Flow Logs delivered to S3 in the text format:
// gzipped, one flow per line, fields separated by spaces, and a first line
// that names the fields. Custom formats reorder and add fields, so every
// object is decoded by the names in its own header. Parquet objects are
// refused with ErrParquet; ctaudit has no Parquet reader.
package flowlog

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Log statuses. NODATA and SKIPDATA rows carry no flow.
const (
	StatusOK       = "OK"
	StatusNoData   = "NODATA"
	StatusSkipData = "SKIPDATA"
)

// Entry is one flow log record. Integer fields the record leaves as "-", or
// that the object's format does not include, are -1; Packets and Bytes are
// 0 then; addresses are the zero netip.Addr; strings are "".
type Entry struct {
	Version     int
	AccountID   string
	InterfaceID string
	SrcAddr     netip.Addr
	DstAddr     netip.Addr
	SrcPort     int
	DstPort     int
	Protocol    int
	Packets     int64
	Bytes       int64
	Start       time.Time
	End         time.Time
	Action      string
	LogStatus   string

	VPCID            string
	SubnetID         string
	InstanceID       string
	TCPFlags         int
	Type             string
	PktSrcAddr       netip.Addr
	PktDstAddr       netip.Addr
	Region           string
	AZID             string
	PktSrcAWSService string
	PktDstAWSService string
	FlowDirection    string
	TrafficPath      int
	RejectReason     string
}

func newEntry() Entry {
	return Entry{Version: -1, SrcPort: -1, DstPort: -1, Protocol: -1, TCPFlags: -1, TrafficPath: -1}
}

// Source is the packet's original source: pkt-srcaddr when the format has
// it and it is set, else srcaddr. Through a NAT gateway or load balancer it
// names the real endpoint rather than the intermediate interface.
func (e Entry) Source() netip.Addr {
	if e.PktSrcAddr.IsValid() {
		return e.PktSrcAddr
	}
	return e.SrcAddr
}

// Dest is the packet's final destination: pkt-dstaddr when set, else dstaddr.
func (e Entry) Dest() netip.Addr {
	if e.PktDstAddr.IsValid() {
		return e.PktDstAddr
	}
	return e.DstAddr
}

var protocolNames = map[int]string{1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 51: "ah", 58: "icmpv6", 132: "sctp"}

// ProtocolName returns the IANA protocol's short name, the number as text
// for protocols without one, or "" when the protocol is unknown.
func (e Entry) ProtocolName() string {
	if e.Protocol < 0 {
		return ""
	}
	if n, ok := protocolNames[e.Protocol]; ok {
		return n
	}
	return strconv.Itoa(e.Protocol)
}

// Service names the destination service, such as "443/tcp". ICMP has no
// ports, so ICMP and ICMPv6 flows, and flows with an unknown port, are named
// by the protocol alone.
func (e Entry) Service() string {
	p := e.ProtocolName()
	if e.Protocol == 1 || e.Protocol == 58 || e.DstPort < 0 {
		return p
	}
	if p == "" {
		return strconv.Itoa(e.DstPort)
	}
	return strconv.Itoa(e.DstPort) + "/" + p
}

type field uint8

const (
	fIgnore field = iota
	fVersion
	fAccountID
	fInterfaceID
	fSrcAddr
	fDstAddr
	fSrcPort
	fDstPort
	fProtocol
	fPackets
	fBytes
	fStart
	fEnd
	fAction
	fLogStatus
	fVPCID
	fSubnetID
	fInstanceID
	fTCPFlags
	fType
	fPktSrcAddr
	fPktDstAddr
	fRegion
	fAZID
	fPktSrcService
	fPktDstService
	fFlowDirection
	fTrafficPath
	fRejectReason
)

// fieldNames maps the header names of every field ctaudit reads. Names not
// listed here are skipped, so formats with newer fields still decode.
var fieldNames = map[string]field{
	"version": fVersion, "account-id": fAccountID, "interface-id": fInterfaceID,
	"srcaddr": fSrcAddr, "dstaddr": fDstAddr, "srcport": fSrcPort, "dstport": fDstPort,
	"protocol": fProtocol, "packets": fPackets, "bytes": fBytes, "start": fStart, "end": fEnd,
	"action": fAction, "log-status": fLogStatus, "vpc-id": fVPCID, "subnet-id": fSubnetID,
	"instance-id": fInstanceID, "tcp-flags": fTCPFlags, "type": fType,
	"pkt-srcaddr": fPktSrcAddr, "pkt-dstaddr": fPktDstAddr, "region": fRegion, "az-id": fAZID,
	"pkt-src-aws-service": fPktSrcService, "pkt-dst-aws-service": fPktDstService,
	"flow-direction": fFlowDirection, "traffic-path": fTrafficPath, "reject-reason": fRejectReason,
}

// nameOf is the reverse of fieldNames, for error messages.
var nameOf = func() map[field]string {
	m := make(map[field]string, len(fieldNames))
	for n, f := range fieldNames {
		m[f] = n
	}
	return m
}()

// Header maps each column of an object's records to a field.
type Header struct {
	cols []field
}

// ParseHeader reads an object's first line. Names may be wrapped as in the
// format string (${srcaddr}). The start field is required, because the scan
// window is applied to it.
func ParseHeader(line string) (Header, error) {
	names := strings.Fields(line)
	if len(names) == 0 {
		return Header{}, errors.New("empty header line")
	}
	h := Header{cols: make([]field, len(names))}
	hasStart := false
	for i, n := range names {
		n = strings.TrimSuffix(strings.TrimPrefix(n, "${"), "}")
		if n != "" && n[0] >= '0' && n[0] <= '9' {
			return Header{}, errors.New("missing header: the first line is a record, not field names")
		}
		f := fieldNames[n]
		h.cols[i] = f
		if f == fStart {
			hasStart = true
		}
	}
	if !hasStart {
		return Header{}, errors.New("header has no start field")
	}
	return h, nil
}

// Parse decodes one record line. The error names the bad field but never
// quotes the record.
func (h Header) Parse(line string) (Entry, error) {
	e := newEntry()
	rest := strings.TrimSpace(line)
	for i, f := range h.cols {
		if rest == "" {
			return Entry{}, fmt.Errorf("%d fields, header has %d", i, len(h.cols))
		}
		var v string
		v, rest, _ = strings.Cut(rest, " ")
		rest = strings.TrimLeft(rest, " ")
		if f == fIgnore || v == "-" {
			continue
		}
		if err := e.set(f, v); err != nil {
			return Entry{}, fmt.Errorf("bad %s field", nameOf[f])
		}
	}
	if rest != "" {
		return Entry{}, fmt.Errorf("more fields than the header's %d", len(h.cols))
	}
	return e, nil
}

func (e *Entry) set(f field, v string) error {
	var err error
	switch f {
	case fVersion:
		e.Version, err = strconv.Atoi(v)
	case fAccountID:
		e.AccountID = v
	case fInterfaceID:
		e.InterfaceID = v
	case fSrcAddr:
		e.SrcAddr, err = netip.ParseAddr(v)
	case fDstAddr:
		e.DstAddr, err = netip.ParseAddr(v)
	case fSrcPort:
		e.SrcPort, err = port(v)
	case fDstPort:
		e.DstPort, err = port(v)
	case fProtocol:
		e.Protocol, err = strconv.Atoi(v)
	case fPackets:
		e.Packets, err = strconv.ParseInt(v, 10, 64)
	case fBytes:
		e.Bytes, err = strconv.ParseInt(v, 10, 64)
	case fStart:
		e.Start, err = unixTime(v)
	case fEnd:
		e.End, err = unixTime(v)
	case fAction:
		e.Action = v
	case fLogStatus:
		e.LogStatus = v
	case fVPCID:
		e.VPCID = v
	case fSubnetID:
		e.SubnetID = v
	case fInstanceID:
		e.InstanceID = v
	case fTCPFlags:
		e.TCPFlags, err = strconv.Atoi(v)
	case fType:
		e.Type = v
	case fPktSrcAddr:
		e.PktSrcAddr, err = netip.ParseAddr(v)
	case fPktDstAddr:
		e.PktDstAddr, err = netip.ParseAddr(v)
	case fRegion:
		e.Region = v
	case fAZID:
		e.AZID = v
	case fPktSrcService:
		e.PktSrcAWSService = v
	case fPktDstService:
		e.PktDstAWSService = v
	case fFlowDirection:
		e.FlowDirection = v
	case fTrafficPath:
		e.TrafficPath, err = strconv.Atoi(v)
	case fRejectReason:
		e.RejectReason = v
	}
	return err
}

func port(v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 65535 {
		return 0, errors.New("port out of range")
	}
	return n, nil
}

func unixTime(v string) (time.Time, error) {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(n, 0).UTC(), nil
}

// ErrParquet is returned for Parquet objects. The engine records it as a
// per-object error, so the scan fails rather than silently skipping data.
var ErrParquet = errors.New("parquet flow log files are not supported; ctaudit reads the text log file format only")

// IsLogKey reports whether a listed key is a flow log object. Parquet keys
// are kept on purpose so that Decode can refuse them by name.
func IsLogKey(key string) bool {
	name := key[strings.LastIndex(key, "/")+1:]
	if !strings.Contains(name, "_vpcflowlogs_") {
		return false
	}
	return strings.HasSuffix(name, ".log.gz") || strings.HasSuffix(name, ".parquet")
}

// maxLine bounds one record line. A record with every field is well under
// 1 KiB.
const maxLine = 64 << 10

// LineError reports record lines of an object that could not be parsed.
// Stream returns it after emitting every record that did parse.
type LineError struct {
	Bad   int
	First error
}

func (e *LineError) Error() string {
	return fmt.Sprintf("%d unparseable lines, first: %v", e.Bad, e.First)
}

// Stream reads one flow log object, gzipped or plain, and calls emit for
// every record, in file order, as it is parsed. Unparseable record lines are
// skipped and reported through a *LineError; a missing or bad header, and
// I/O and gzip errors, are returned as they happen. Records emitted before
// an I/O error stay emitted.
func Stream(key string, r io.Reader, emit func(Entry)) error {
	if strings.HasSuffix(key, ".parquet") {
		return ErrParquet
	}
	br := bufio.NewReader(r)
	var src io.Reader = br
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return fmt.Errorf("gzip: %w", err)
		}
		defer zr.Close()
		src = zr
	}
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	var (
		h          Header
		haveHeader bool
		lineErr    *LineError
	)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !haveHeader {
			var err error
			if h, err = ParseHeader(line); err != nil {
				return fmt.Errorf("header: %w", err)
			}
			haveHeader = true
			continue
		}
		e, err := h.Parse(line)
		if err != nil {
			if lineErr == nil {
				lineErr = &LineError{First: err}
			}
			lineErr.Bad++
			continue
		}
		emit(e)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if lineErr != nil {
		return lineErr
	}
	return nil
}

// Decode collects Stream's records. On a *LineError it returns the records
// that parsed with the error; on any other error it returns no records.
func Decode(key string, r io.Reader) ([]Entry, error) {
	var out []Entry
	err := Stream(key, r, func(e Entry) { out = append(out, e) })
	var le *LineError
	if err != nil && !errors.As(err, &le) {
		return nil, err
	}
	return out, err
}
