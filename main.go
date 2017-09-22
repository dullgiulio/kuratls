package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
)

// TODO: REST interface to add profiles (domain generator)
// TODO: Store to put certificates and keys as PEM
// TODO: REST interface to fetch generated PEMs. Must wait for certs that are being generated!

func main() {
	rootCrt := flag.String("root", "", "Root CA certificate file to load (optional)")
	flag.Parse()
	var parent *x509.Certificate
	if *rootCrt == "" {
		// TODO: generate root CRT
	} else {
		var err error
		parent, err = loadCertificateFile(*rootCrt)
		if err != nil {
			log.Fatal("cannot load certificate from %s: %v", *rootCrt, err)
		}
		fmt.Printf("%+v\n", parent)
	}
	cr := &certReq{
		isRoot:     false,
		commonName: "*.t3env.int.kn",
		name: pkix.Name{
			Country:            []string{"Estonia"},
			Organization:       []string{"TestOrg"},
			OrganizationalUnit: []string{"TestUnit"},
			Locality:           []string{"Locality"},
			Province:           []string{"Province"},
			StreetAddress:      []string{"Address"},
			PostalCode:         []string{"Postal Code"},
		},
	}
	k, err := newECDSAKeys()
	//k, err := newRSAKeys(0) // Use this in production, slower but more supported
	if err != nil {
		log.Fatalf("cannot generate asymmetric key pair: %v", err)
	}
	cert, err := cr.generate(k, parent)
	if err != nil {
		log.Fatalf("cannot generate root certificate: %v", err)
	}
	fmt.Printf("CERT:\n%s\n\nPrivate:\n%s\n\nPublic:\n%s\n", cert.cert, cert.priv, cert.pub)
}
