package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {
	clientCert, err := tls.LoadX509KeyPair("../certs/service.crt", "../certs/serviceCert.key")
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
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://127.0.0.1:8000/")
	if err != nil {
		log.Fatal("GET:", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Status: %s\nBody:\n%s\n", resp.Status, body)
}
