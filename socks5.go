// Package socks5 provides a convenient way to
// implement a socks5 server with flexible backends.
package socks5

// VERSION -> socks5
const VERSION = 5

// Method
const (
	NOAUTH byte = iota
	GSSAPI
	UAP
)

// CMD
const (
	_ byte = iota
	CONNECT
	BIND
	ASSOCIATE
)

// RSV Reserved
const RSV byte = 0

// Address Type
const (
	_ byte = iota
	IPV4T
	_
	DOMAIN
	IPV6T
)

// Replies
const (
	SUCC     byte = iota
	FAIL          // general SOCKS server failure
	FORBID        // connection not allowed by ruleset
	NUNREACH      // Network unreachable
	HUNREACH      // Host unreachable
	REFUSE        // Connection refused
	EXPIRE        // TTL expired
	NSUPPORT      // Command not supported
	ANSUP         // Address type not supported

	NOACCEPT byte = 255
)
