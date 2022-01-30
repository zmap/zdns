package zdns

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

func init() {
	rePort = regexp.MustCompile(":\\d+$")      // string ends with potential port number
	reV6 = regexp.MustCompile("^([0-9a-f]*:)") // string starts like valid IPv6 address
}
