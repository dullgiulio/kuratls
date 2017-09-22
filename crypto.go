package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

type certReq struct {
	isRoot     bool
	commonName string
	domains    []string
	name       pkix.Name
}

type keys interface {
	bytes() (priv, pub []byte)
	private() interface{}
	public() interface{}
	algo() x509.SignatureAlgorithm
}

type rsaKeys struct {
	priv        *rsa.PrivateKey
	pub         crypto.PublicKey
	bpriv, bpub []byte
}

func newRSAKeys(bits int) (*rsaKeys, error) {
	var err error
	k := &rsaKeys{}
	if bits == 0 {
		bits = 4096
	}
	k.priv, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("cannot generate RSA key (%d bits): %v", bits, err)
	}
	k.pub = k.priv.Public()
	k.bpriv = x509.MarshalPKCS1PrivateKey(k.priv)
	k.bpub, err = x509.MarshalPKIXPublicKey(k.pub)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal RSA public key: %v", err)
	}
	return k, nil
}

func (k *rsaKeys) bytes() (priv, pub []byte) {
	return k.bpriv, k.bpub
}

func (k *rsaKeys) private() interface{} {
	return k.priv
}

func (k *rsaKeys) public() interface{} {
	return k.pub
}

func (k *rsaKeys) algo() x509.SignatureAlgorithm {
	return x509.SHA512WithRSA
}

type ecdsaKeys struct {
	priv        *ecdsa.PrivateKey
	pub         interface{}
	bpriv, bpub []byte
}

func newECDSAKeys() (*ecdsaKeys, error) {
	var err error
	k := &ecdsaKeys{}
	curve := elliptic.P224() // Chosen at random, read which one to use
	k.priv, err = ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate ECDSA key: %v", err)
	}
	k.pub = k.priv.Public()
	k.bpriv, err = x509.MarshalECPrivateKey(k.priv)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal ECDSA private key: %v", err)
	}
	k.bpub, err = x509.MarshalPKIXPublicKey(k.pub)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal ECDSA public key: %v", err)
	}
	return k, nil
}

func (k *ecdsaKeys) bytes() (priv, pub []byte) {
	return k.bpriv, k.bpub
}

func (k *ecdsaKeys) private() interface{} {
	return k.priv
}

func (k *ecdsaKeys) public() interface{} {
	return k.pub
}

func (k *ecdsaKeys) algo() x509.SignatureAlgorithm {
	return x509.ECDSAWithSHA512
}

func keysToPem(k keys) ([]byte, []byte) {
	priv, pub := k.bytes()
	return pem.EncodeToMemory(&pem.Block{Bytes: priv, Type: "PRIVATE KEY"}),
		pem.EncodeToMemory(&pem.Block{Bytes: pub, Type: "PUBLIC KEY"})
}

func keysHash(k keys) ([]byte, error) {
	pub, _ := k.bytes()
	h := sha1.New()
	_, err := h.Write(pub)
	if err != nil {
		return nil, err
	}
	c := h.Sum(nil)
	return c, nil
}

type cert struct {
	cert, priv, pub []byte
}

func loadCertificateFile(name string) (*x509.Certificate, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("cannot open file: %v", err)
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("cannot read certificate file: %v", err)
	}
	return loadCertificate(data)
}

func loadCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("cannot decode PEM: no PEM data found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("cannot use PEM: expects a PEM CERTIFICATE section")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse x509 certificate: %v", err)
	}
	return crt, nil
}

func (r *certReq) generate(k keys, parent *x509.Certificate) (*cert, error) {
	now := time.Now()
	authorityKeyId, err := keysHash(k)
	if err != nil {
		return nil, fmt.Errorf("cannot compute checksum of public key: %v", err)
	}
	serialNumber := big.NewInt(int64(now.Nanosecond())) // Insecure, but who cares?
	usagesCA := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	r.name.SerialNumber = fmt.Sprintf("%s", serialNumber)
	r.name.CommonName = r.commonName
	if r.isRoot {
		r.domains = []string{r.commonName}
	}
	tmpl := &x509.Certificate{
		IsCA:                  r.isRoot,
		MaxPathLenZero:        r.isRoot,
		KeyUsage:              usagesCA,
		DNSNames:              r.domains,
		NotAfter:              now.Add(200 * 365 * 24 * time.Hour), // roughly 200 years
		NotBefore:             now.Add(-24 * time.Hour),
		SerialNumber:          serialNumber,
		SignatureAlgorithm:    k.algo(),
		BasicConstraintsValid: true,
		AuthorityKeyId:        authorityKeyId,
		Subject:               r.name,
		Issuer:                r.name,
	}
	if parent == nil {
		parent = tmpl
	}
	if !parent.IsCA {
		return nil, errors.New("expected parent certificate to be a CA, but it is not")
	}
	crt, err := x509.CreateCertificate(rand.Reader, tmpl, parent, k.public(), k.private())
	if err != nil {
		return nil, fmt.Errorf("cannot generate certificate: %v", err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Bytes: crt, Type: "CERTIFICATE"})
	pemPriv, pemPub := keysToPem(k)
	return &cert{pemCert, pemPriv, pemPub}, nil
}
