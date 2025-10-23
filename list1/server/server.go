package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func must(b []byte, err error) []byte {
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func loadFirstCACert(pemBytes []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("no CERTIFICATE block found in client-ca.crt")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

func main() {
	gin.SetMode(gin.DebugMode)

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"hello": "tls"}) })

	srvCert, err := tls.LoadX509KeyPair("../certs/service.crt", "../certs/serviceCert.key")
	caPEM := must(os.ReadFile("/home/dalinarkholin/GolandProjects/BOW/list1/certs/bow.inc.ca.crt"))
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(caPEM) {
		log.Fatal("append client CA failed")
	}

	caCert, err := loadFirstCACert(caPEM)
	if err != nil {
		log.Fatalf("parse client-ca: %v", err)
	}
	pin := sha256.Sum256(caCert.RawSubjectPublicKeyInfo)
	log.Printf("Pinned client-CA SPKI sha256(base64): %s", base64.StdEncoding.EncodeToString(pin[:]))

	tcfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 {
				return x509.CertificateInvalidError{}
			}
			root := cs.VerifiedChains[0][len(cs.VerifiedChains[0])-1]
			got := sha256.Sum256(root.RawSubjectPublicKeyInfo)
			if got != pin {
				return x509.UnknownAuthorityError{}
			}
			// (opcjonalnie) sprawdź EKU clientAuth:
			leaf := cs.VerifiedChains[0][0]
			okEKU := false
			for _, eku := range leaf.ExtKeyUsage {
				if eku == x509.ExtKeyUsageClientAuth {
					okEKU = true
					break
				}
			}
			if !okEKU {
				return x509.CertificateInvalidError{}
			}
			return nil
		},
	}

	httpsSrv := &http.Server{
		Addr:      ":8000",
		Handler:   r,
		TLSConfig: tcfg,
	}

	if err := httpsSrv.ListenAndServeTLS("../certs/service.crt", "../certs/serviceCert.key"); err != nil {
		log.Fatalf("https server: %v", err)
	}
}
