package main

import (
	"encoding/json"
	"sort"
)

type Node struct {
	NodeId int   `json:"nodeId"`
	Edge   []int `json:"edge"`
	color  int
}

type Graph struct {
	Nodes []Node `json:"nodes"`
}

var graph = Graph{
	Nodes: []Node{
		{2,
			[]int{1, 3, 4, 5},
			1},
		{0,
			[]int{1, 6},
			3},
		{1,
			[]int{0, 2},
			2},
		{3,
			[]int{2},
			2},
		{4,
			[]int{2},
			2},
		{5,
			[]int{2, 6, 7},
			2},
		{6,
			[]int{0, 5},
			1},
		{7,
			[]int{5},
			1},
	},
}

type Seq[V any] func(yield func(V) bool)

func (g *Graph) Iter() Seq[Node] {
	sort.Slice(g.Nodes, func(i, j int) bool {
		return g.Nodes[i].NodeId < g.Nodes[j].NodeId
	})

	return func(yield func(Node) bool) {
		for _, v := range g.Nodes {
			if !yield(v) {
				return
			}
		}
	}
}

func GetJsonGraph() string {
	jsoned, _ := json.Marshal(graph)
	return string(jsoned)
}

func GetGraph() Graph {
	return graph
}
