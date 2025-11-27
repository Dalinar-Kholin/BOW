package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
)

func Verify() {
	client := &http.Client{}

	r1, err := client.Get("http://127.0.0.1:8080/getGraph")
	if err != nil {
		panic(err)
	}

	var graph Graph
	json.NewDecoder(r1.Body).Decode(&graph)

	r2, err := client.Get("http://127.0.0.1:8080/getEncryptedGraph")
	if err != nil {
		panic(err)
	}

	var encryptedGraph EncryptedGraph
	if err := json.NewDecoder(r2.Body).Decode(&encryptedGraph); err != nil {
		panic(err)
	}
	index := make([]byte, 2)
	if _, err := rand.Read(index); err != nil {
		panic(err)
	}

	id1 := uint(index[0]) % uint(len(graph.Nodes))

	node := graph.Nodes[id1]
	l := len(node.Edge)
	id2 := node.Edge[int(index[1])%l]

	if slices.Index(graph.Nodes[id1].Edge, id2) == -1 {
		return
	}

	r3, err := client.Get(fmt.Sprintf("http://127.0.0.1:8080/getColors?id1=%d&id2=%d&sha=%s", id1, id2, encryptedGraph.Sha))

	if err != nil {
		panic(err)
	}
	var res []ResultEncryptedNode
	json.NewDecoder(r3.Body).Decode(&res)

	res0, _ := json.Marshal(res[0])
	sum0 := sha512.Sum512(res0)
	if encryptedGraph.Nodes[slices.IndexFunc(encryptedGraph.Nodes, func(e EncryptedNode) bool {
		return uint(e.NodeId) == id1
	})].Hash != hex.EncodeToString(sum0[:]) {
		panic("invalid hash1")
	}

	res1, _ := json.Marshal(res[1])
	sum1 := sha512.Sum512(res1)

	if encryptedGraph.Nodes[slices.IndexFunc(encryptedGraph.Nodes, func(e EncryptedNode) bool {
		return e.NodeId == id2
	})].Hash != hex.EncodeToString(sum1[:]) {
		panic("invalid hash2")
	}

	if res[0].Color == res[1].Color {
		fmt.Printf("ress := %v\n", res)
		panic("same Color")
	}
}
