package lib

import (
	"github.com/rs/zerolog"
)

type Options struct {
	// Logging
	Logger *zerolog.Logger
	Debug bool

	// Scan options
	TargetFile string
	Threads int
	AllowInsecureURIs bool
	Identifier string
	Proxy string
	FollowRedirect bool
	Sleep int
	RunBaseline bool
	RunSafe bool
	RunExploit bool
	HTTPGet bool
	HTTPPost bool
}

func NewOptions() *Options {
	return &Options{}
}