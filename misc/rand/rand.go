package rand

import (
	"crypto/rand"
	"errors"
	"math/big"
)

var (
	alpha []string // used for random value generation
)

func init() {
	// populate alpha with all upper and lowercase letters
	for _, s := range [][]rune{{'a', 'z'}, {'A', 'Z'}, {'0', '9'}} {
		for l := s[0]; l <= s[1]; l++ {
			alpha = append(alpha, string(l))
		}
	}
}

func Letter() (l string, err error) {
	var i *big.Int
	if i, err = rand.Int(rand.Reader, big.NewInt(int64(len(alpha)))); err != nil {
		return
	}
	return alpha[i.Int64()], nil
}

func String(maxLen int64) (s string, err error) {
	var l string
	for i := int64(0); i < maxLen; i++ {
		l, err = Letter()
		if err != nil {
			return s, errors.New("failed to generate random letter: " + err.Error())
		}
		s += l
	}
	return
}
