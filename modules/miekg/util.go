package miekg

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/zmap/zdns"
)

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

func TranslateMiekgErrorCode(err int) zdns.Status {
	return zdns.Status(dns.RcodeToString[err])
}

func isStatusAnswer(s zdns.Status) bool {
	if s == zdns.STATUS_NOERROR || s == zdns.STATUS_NXDOMAIN {
		return true
	}
	return false
}

func questionFromAnswer(a Answer) Question {
	return Question{Name: a.Name, Type: a.RrType, Class: a.RrClass}
}

func nameIsBeneath(name, layer string) (bool, string) {
	name = strings.ToLower(name)
	layer = strings.ToLower(layer)
	name = strings.TrimSuffix(name, ".")
	if layer == "." {
		return true, name
	}

	if strings.HasSuffix(name, "."+layer) || name == layer {
		return true, name
	}
	return false, ""
}

func nextAuthority(name, layer string) (string, error) {
	// We are our own authority for PTRs
	// (This is dealt with elsewhere)
	if strings.HasSuffix(name, "in-addr.arpa") && layer == "." {
		return "in-addr.arpa", nil
	}

	idx := strings.LastIndex(name, ".")
	if idx < 0 || (idx+1) >= len(name) {
		return name, nil
	}
	if layer == "." {
		return name[idx+1:], nil
	}

	if !strings.HasSuffix(name, layer) {
		return "", errors.New("Server did not provide appropriate resolvers to continue recursion")
	}

	// Limit the search space to the prefix of the string that isnt layer
	idx = strings.LastIndex(name, layer) - 1
	if idx < 0 || (idx+1) >= len(name) {
		// Out of bounds. We are our own authority
		return name, nil
	}
	// Find the next step in the layer
	idx = strings.LastIndex(name[0:idx], ".")
	next := name[idx+1:]
	return next, nil
}

func checkGlue(server string, depth int, result Result) (Result, zdns.Status) {
	for _, additional := range result.Additional {
		ans, ok := additional.(Answer)
		if !ok {
			continue
		}
		if ans.Type == "A" && strings.TrimSuffix(ans.Name, ".") == server {
			var retv Result
			retv.Authorities = make([]interface{}, 0)
			retv.Answers = make([]interface{}, 0)
			retv.Additional = make([]interface{}, 0)
			retv.Answers = append(retv.Answers, ans)
			return retv, zdns.STATUS_NOERROR
		}
	}
	var r Result
	return r, zdns.STATUS_ERROR
}

func makeVerbosePrefix(depth int, threadID int) string {
	return fmt.Sprintf("THREADID %06d,DEPTH %02d", threadID, depth) + ":" + strings.Repeat("  ", 2*depth)
}
