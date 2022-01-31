package util

import "regexp"

var rePort *regexp.Regexp
var reV6 *regexp.Regexp

func AddDefaultPortToDNSServerName(s string) string {
	if !rePort.MatchString(s) {
		return s + ":53"
	} else if reV6.MatchString(s) {
		return "[" + s + "]:53"
	} else {
		return s
	}
}

// getDefaultResolvers returns a slice of default DNS resolvers to be used when no system resolvers could be discovered.
func GetDefaultResolvers() []string {
	return []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"}
}

func init() {
	rePort = regexp.MustCompile(":\\d+$")      // string ends with potential port number
	reV6 = regexp.MustCompile("^([0-9a-f]*:)") // string starts like valid IPv6 address
}
