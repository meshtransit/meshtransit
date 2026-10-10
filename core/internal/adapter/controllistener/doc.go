// Package controllistener is the public TLS listener of a control process.
// It bounds connections before TLS, serves HTTP/1.1 only, and hands each
// request to the control routes (MTCP v1 and the relay authority), which
// own the sessions they hijack.
package controllistener
