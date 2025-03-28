package eavesarp_ng

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	gs "github.com/impostorkeanu/gosplit"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
)

var (
	randAlpha []string // used for random value generation
)

type (

	// TLSCertCache is a map that serves as a grow-only cache, i.e.,
	// once a certificate is cached, it exists forever.
	//
	// Keys are of type CertCacheKey.
	TLSCertCache struct {
		sync.Map
		cfg Cfg
	}

	// CertCacheKey contains md5 characteristics about dynamically
	// generated certificates.
	CertCacheKey struct {
		commonName string
		ips        []string
		dnsNames   []string
		parsedIPs  []net.IP
		md5        string
	}
)

func init() {
	// populate randAlpha with all upper and lowercase letters
	for _, s := range [][]rune{{'a', 'z'}, {'A', 'Z'}, {'0', '9'}} {
		for l := s[0]; l <= s[1]; l++ {
			randAlpha = append(randAlpha, string(l))
		}
	}
}

func randLetter() (l string, err error) {
	var i *big.Int
	if i, err = rand.Int(rand.Reader, big.NewInt(int64(len(randAlpha)))); err != nil {
		return
	}
	return randAlpha[i.Int64()], nil
}

func randString(maxLen int64) (s string, err error) {
	var l string
	for i := int64(0); i < maxLen; i++ {
		l, err = randLetter()
		if err != nil {
			return s, errors.New("failed to generate random letter: " + err.Error())
		}
		s += l
	}
	return
}

func NewCertCacheKey(commonName string, ips []string, dnsNames []string) (*CertCacheKey, error) {

	// string builder to capture all string details
	sB := strings.Builder{}
	sB.WriteString(commonName)

	// copy, sort, and convert ip addresses
	iBuff := ips[:]
	slices.Sort(iBuff)
	var nIPs []net.IP
	for _, i := range iBuff {
		ip := net.ParseIP(i)
		if ip == nil {
			return nil, fmt.Errorf("invalid ip address: %s", ip)
		}
		sB.WriteString(ip.String())
		nIPs = append(nIPs, ip)
	}

	// copy and sort dns names
	dBuff := dnsNames[:]
	slices.Sort(dBuff)
	for _, d := range dBuff {
		sB.WriteString(d)
	}

	// generate a md5 string and bind it to the key
	m := md5.New()
	m.Write([]byte(sB.String()))

	return &CertCacheKey{
		commonName: commonName,
		ips:        ips,
		dnsNames:   dBuff,
		parsedIPs:  nIPs,
		md5:        fmt.Sprintf("%x", m.Sum(nil)),
	}, nil
}

func (ck *CertCacheKey) MD5() string {
	return ck.md5
}

func (c *TLSCertCache) Get(key CertCacheKey) (crt *tls.Certificate, err error) {

	//==================================
	// FIND AND RETURN KNOWN CERTIFICATE
	//==================================

	v, found := c.Load(key.md5)
	if found {
		// return the retrieved certificate
		return v.(*tls.Certificate), err
	}

	//=================================
	// GENERATE AND CACHE A CERTIFICATE
	//=================================

	// generate and return a new certificate
	pK := c.cfg.tls.keygen.Generate()
	if pK.Err() != nil {
		return nil, pK.Err()
	}

	// TODO learn your lazy ass some reflection :P
	//  ~~~ this is sort of ridiculous! lol ~~~

	// many of these fields are to be randomized
	name := pkix.Name{
		Country:            nil,
		Organization:       nil,
		OrganizationalUnit: nil,
		Locality:           nil,
		Province:           nil,
		SerialNumber:       "",
		CommonName:         key.commonName,
	}

	name.SerialNumber, err = randString(int64(30)) // randomize serial number

	// additional fields to randomize
	randFields := []*[]string{&name.Country, &name.Organization,
		&name.OrganizationalUnit, &name.Locality,
		&name.Province}

	// randomize values for fields
	for _, f := range randFields {
		l, err := rand.Int(rand.Reader, big.NewInt(int64(20))) // random length for the field
		if err != nil {
			return nil, errors.New("failed to generate random number: " + err.Error())
		}

		s, err := randString(l.Int64()) // random string for the field
		if err != nil {
			return nil, errors.New("failed to generate random string: " + err.Error())
		}

		// update the field
		*f = append(*f, s)
	}

	// generate a self-signed certificate
	crt, err = gs.GenSelfSignedCert(name, key.parsedIPs, key.dnsNames, pK)

	if err == nil {
		c.Store(key.md5, crt)
	}

	return
}
