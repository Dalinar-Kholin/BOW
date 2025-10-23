package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"slices"
	"strconv"
	"sync"

	"github.com/gin-gonic/gin"
)

var clientCert = "/home/dalinarkholin/GolandProjects/BOW/list1/zad3/certs/client.crt"
var clientKey = "/home/dalinarkholin/GolandProjects/BOW/list1/zad3/certs/client.key"
var serverCert = "/home/dalinarkholin/GolandProjects/BOW/list1/zad3/certs/server.crt"
var serverKey = "/home/dalinarkholin/GolandProjects/BOW/list1/zad3/certs/server.key"
var caCert = "/home/dalinarkholin/GolandProjects/BOW/list1/zad3/certs/ca.crt"

var Ports = []string{"8000", "8001", "8002"}

var startChain = false
var random = 0

func main() {
	server := makeTLSServer()
	var wg sync.WaitGroup
	myPort := os.Args[1]

	go func(wg *sync.WaitGroup) {
		wg.Add(1)
		server.ListenAndServeTLS(serverCert, serverKey)
	}(&wg)

	for _, port := range Ports {
		if port == myPort {
			continue
		}
		client := makeClient()
		for {
			resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%s/healthz", port))
			if err != nil {
				continue
			}
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
	}
	fmt.Printf("Donen\n")
	var start string
	fmt.Scanf("%s", &start)
	startChain = true
	newPort := Ports[(slices.Index(Ports, myPort)+1)%len(Ports)]
	number := rand.Intn(100)
	randomness := rand.Intn(100)
	random = randomness
	fmt.Printf("wylosowano := %d\n", number)
	_, err := makeClient().Get(fmt.Sprintf("https://127.0.0.1:%s/calc?calced=%d", newPort, number+randomness))
	if err != nil {
		panic(err)
	}

	wg.Wait()
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

func must(b []byte, err error) []byte {
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func makeTLSServer() *http.Server {
	r := gin.New()
	r.Use(gin.Recovery())
	myPort := os.Args[1]
	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"hello": "tls"}) })

	// zaczynam z klienta 2 przesyła zapytanie do 3 calc z R + val następnie

	r.GET("/getResult", func(c *gin.Context) {
		fmt.Printf("obliczono wspólnie %s\n", c.Request.URL.Query().Get("calced"))
	})

	r.GET("/calc", func(c *gin.Context) {
		if startChain {
			data, _ := strconv.Atoi(c.Request.URL.Query().Get("calced"))
			data -= random
			fmt.Printf("obliczono wspólnie %d\n", data)
			for _, port := range Ports {
				if port == myPort {
					continue
				}
				client := makeClient()
				for {
					resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%s/getResult?calced=%d", port, data))
					if err != nil {
						continue
					}
					if resp.StatusCode == http.StatusOK {
						break
					}
				}
			}
			startChain = false
			random = 0
			return
		}
		data, _ := strconv.Atoi(c.Request.URL.Query().Get("calced"))
		requestRandom := rand.Intn(100)
		fmt.Printf("random for this request := %v\n", requestRandom)
		newPort := Ports[(slices.Index(Ports, myPort)+1)%len(Ports)]
		makeClient().Get(fmt.Sprintf("https://127.0.0.1:%s/calc?calced=%d", newPort, requestRandom+data))
	})

	srvCert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	caPEM := must(os.ReadFile(caCert))
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
		Addr:      fmt.Sprintf(":%s", myPort),
		Handler:   r,
		TLSConfig: tcfg,
	}
	return httpsSrv
}

func makeClient() *http.Client {
	clientCert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		log.Fatal("LoadX509KeyPair:", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12,
	}

	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
	}
	return &http.Client{Transport: tr}
}
