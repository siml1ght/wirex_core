package applog

import "log"

var verbose bool

func SetVerbose(v bool) { verbose = v }

func Verbose() bool { return verbose }

// Printf is a no-op unless --verbose. The client's stdout is a binary frame
// channel to nekobox, so even stderr chatter stays off in release builds.
func Printf(format string, args ...any) {
	if verbose {
		log.Printf(format, args...)
	}
}
