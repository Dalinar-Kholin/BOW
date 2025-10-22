package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"slices"
)

type EncryptedGraph struct {
	Nodes []EncryptedNode `json:"nodes"`
	Nonce []byte
	Sha   string `json:"sha"`
}

type EncryptedNode struct {
	NodeId int `json:"nodeId"`
	salt   []byte
	color  byte
	Hash   string `json:"hash"`
	edge   []int
}

type ResultEncryptedNode struct {
	NodeId int    `json:"nodeId"`
	Salt   []byte `json:"salt"`
	Color  byte   `json:"color"`
	Edge   []int  `json:"edge"`
}

var mapa map[string]EncryptedGraph = make(map[string]EncryptedGraph)

func GetEncryptedGraph() *EncryptedGraph {
	colors := make([]byte, 3)
	if _, err := rand.Read(colors); err != nil {
		panic(err)
	}

	nonce := make([]byte, 64)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	result := &EncryptedGraph{
		[]EncryptedNode{},
		nonce,
		"",
	}

	takeGraph := GetGraph()
	for x := range takeGraph.Iter() {
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			panic(err)
		}
		edge := make([]int, len(x.Edge))
		copy(edge, x.Edge)

		newNode := EncryptedNode{
			NodeId: x.NodeId,
			salt:   salt,
			color:  colors[x.color-1],
			edge:   edge,
			Hash:   "",
		}
		jsoned, err := json.Marshal(ResultEncryptedNode{
			newNode.NodeId, newNode.salt, newNode.color, newNode.edge,
		})
		if err != nil {
			panic(err)
		}
		sum := sha512.Sum512(jsoned)
		newNode.Hash = hex.EncodeToString(sum[:])
		result.Nodes = append(result.Nodes, newNode)
	}
	jsoned, err := json.Marshal(result)
	if err != nil {
		panic(err)
	}
	sum := sha512.Sum512(jsoned)
	result.Sha = hex.EncodeToString(sum[:])
	mapa[result.Sha] = *result
	return result
}

func GetColors(id1, id2 int, sha string) []ResultEncryptedNode {
	graph := mapa[sha]
	if !slices.Contains(graph.Nodes[slices.IndexFunc(graph.Nodes, func(g EncryptedNode) bool { return g.NodeId == id1 })].edge, id2) {
		panic("nodes are not a neighbor")
	}
	node1 := graph.Nodes[slices.IndexFunc(graph.Nodes, func(g EncryptedNode) bool { return g.NodeId == id1 })]
	node2 := graph.Nodes[slices.IndexFunc(graph.Nodes, func(g EncryptedNode) bool { return g.NodeId == id2 })]

	delete(mapa, sha)

	return []ResultEncryptedNode{
		{node1.NodeId, node1.salt, node1.color, node1.edge},
		{node2.NodeId, node2.salt, node2.color, node2.edge},
	}
}
