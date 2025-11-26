package PerfectHiding

import (
	"crypto/sha512"
	"math/big"

	"github.com/EncEve/crypto/dh"
)

var grp = dh.RFC3526_2048() // p,g z RFC 3526, 2048-bit

var p = grp.P
var g = grp.G
var q = big.NewInt(0).Div(big.NewInt(0).Sub(p, big.NewInt(1)), big.NewInt(2))

func Commit(m, r string) *big.Int {
	M := HashToScalar([]byte("m:" + m))
	R := HashToScalar([]byte("r:" + r))

	gm := new(big.Int).Exp(g, M, p)
	hr := new(big.Int).Exp(deriveH(), R, p)

	C := new(big.Int).Mul(gm, hr)
	C.Mod(C, p)
	return C
}

func Unpack(m, r string, C *big.Int) bool {
	M := HashToScalar([]byte("m:" + m))
	R := HashToScalar([]byte("r:" + r))

	gm := new(big.Int).Exp(g, M, p)
	hr := new(big.Int).Exp(deriveH(), R, p)

	calcedC := new(big.Int).Mul(gm, hr)
	calcedC.Mod(calcedC, p)
	return calcedC.Cmp(C) == 0
}

func deriveH() *big.Int {
	sha := sha512.New()
	// domena + parametry, ale NIE m,r
	sha.Write([]byte("pedersen-h-generator"))
	sha.Write(p.Bytes())
	sha.Write(g.Bytes())
	sum := sha.Sum(nil)

	// hash -> wykładnik w Z_q
	e := new(big.Int).SetBytes(sum)
	e.Mod(e, q)
	if e.Sign() == 0 {
		e.SetInt64(1)
	}

	h := new(big.Int).Exp(g, e, p)
	return h
}

func HashToScalar(data []byte) *big.Int {
	sum := sha512.Sum512(data)
	x := new(big.Int).SetBytes(sum[:])
	x.Mod(x, q)
	if x.Sign() == 0 {
		x.SetInt64(1) // avoid zero exponent
	}
	return x
}
