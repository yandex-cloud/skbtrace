// +build !amd64

package skbtrace

type ArchitectureByteOrderIsNotRecognised struct{}

var HostEndian = ArchitectureByteOrderIsNotRecognised{}
