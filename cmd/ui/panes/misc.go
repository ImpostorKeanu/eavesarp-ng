package panes

import (
	"strings"
)

// greaterLength will split a string on newlines and set i
// to the longest length line so long as it is greater than
// the supplied value.
func greaterLength(s string, i *int) {
	for _, x := range strings.Split(s, "\n") {
		if len(x) > *i {
			*i = len(x)
		}
	}
}

// emptyOrDefault sets the value of s to d if it's currently
// empty.
func emptyOrDefault(s *string, d string) {
	if *s == "" {
		*s = d
	}
}
