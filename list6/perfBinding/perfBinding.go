package perfBinding

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
)

// PublicKey represents the public parameters (N, A).
type PublicKey struct {
	N *big.Int // Blum modulus N = p*q
	A *big.Int // quadratic non-residue mod p and q, Jacobi(A|N) = +1
}

// SecretKey holds the factorization (for setup/testing).
type SecretKey struct {
	P *big.Int
	Q *big.Int
}

// Commitment is the committed value along with randomness.
// In a real protocol, the committer stores only (r, b) locally;
// the receiver only sees C.
type Commitment struct {
	C *big.Int // commitment value in Z_N
}

// GenerateBlumPrimes generates a prime p ≡ 3 (mod 4) of given bit length.
func GenerateBlumPrime(bits int) (*big.Int, error) {
	for {
		p, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		// Check p ≡ 3 (mod 4)
		mod4 := new(big.Int).Mod(p, big.NewInt(4))
		if mod4.Cmp(big.NewInt(3)) == 0 {
			return p, nil
		}
	}
}

// GenerateBlumModulus generates N = p*q with p,q Blum primes.
func GenerateBlumModulus(bits int) (*PublicKey, *SecretKey, error) {
	// We split bits approximately equally between p and q.
	pBits := bits / 2
	qBits := bits - pBits

	p, err := GenerateBlumPrime(pBits)
	if err != nil {
		return nil, nil, err
	}
	q, err := GenerateBlumPrime(qBits)
	if err != nil {
		return nil, nil, err
	}

	N := new(big.Int).Mul(p, q)

	A, err := FindQuadraticNonResidueJacobiPlusOne(N, p, q)
	if err != nil {
		return nil, nil, err
	}

	pk := &PublicKey{N: N, A: A}
	sk := &SecretKey{P: p, Q: q}
	return pk, sk, nil
}

// LegendreSymbol computes the Legendre symbol (a|p) for an odd prime p.
// Returns: 1, -1, or 0 (if gcd(a,p) != 1).
func LegendreSymbol(a, p *big.Int) int {
	zero := big.NewInt(0)
	one := big.NewInt(1)

	aMod := new(big.Int).Mod(a, p)
	if aMod.Cmp(zero) == 0 {
		return 0
	}

	// exponent = (p-1)/2
	exp := new(big.Int).Sub(p, one)
	exp.Rsh(exp, 1)

	res := new(big.Int).Exp(aMod, exp, p)
	if res.Cmp(one) == 0 {
		return 1
	}

	// res == p-1 ≡ -1 (mod p)?
	pMinusOne := new(big.Int).Sub(p, one)
	if res.Cmp(pMinusOne) == 0 {
		return -1
	}

	// Should not happen for a coprime with p, but keep as 0.
	return 0
}

// FindQuadraticNonResidueJacobiPlusOne finds A in Z_N* that is
// a quadratic non-residue mod p and q, hence Jacobi(A|N) = +1.
func FindQuadraticNonResidueJacobiPlusOne(N, p, q *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	NMinusOne := new(big.Int).Sub(N, one)

	for {
		// Sample A uniformly from [2, N-1]
		A, err := rand.Int(rand.Reader, NMinusOne)
		if err != nil {
			return nil, err
		}
		A.Add(A, two) // shift to [2, N]

		// Ensure gcd(A,N) = 1
		if new(big.Int).GCD(nil, nil, A, N).Cmp(one) != 0 {
			continue
		}

		lp := LegendreSymbol(A, p)
		lq := LegendreSymbol(A, q)

		// We want A to be non-residue mod p and q: (A|p) = (A|q) = -1
		if lp == -1 && lq == -1 {
			// Then Jacobi(A|N) = (A|p)(A|q) = (-1)*(-1) = +1
			return A, nil
		}
	}
}

// randomInZNStar samples a random r in Z_N* (1 <= r < N, gcd(r,N)=1).
func randomInZNStar(N *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	for {
		r, err := rand.Int(rand.Reader, N)
		if err != nil {
			return nil, err
		}
		if r.Sign() == 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, r, N).Cmp(one) == 0 {
			return r, nil
		}
	}
}

// Commit implements Blum's bit-commitment:
//
//	b = 0: C = r^2 mod N
//	b = 1: C = A * r^2 mod N
//
// It returns the commitment C and the randomness r (needed to open).
func Commit(pk *PublicKey, b int) (*Commitment, *big.Int, error) {
	if b != 0 && b != 1 {
		return nil, nil, fmt.Errorf("bit must be 0 or 1")
	}
	r, err := randomInZNStar(pk.N)
	if err != nil {
		return nil, nil, err
	}

	// r2 = r^2 mod N
	r2 := new(big.Int).Mul(r, r)
	r2.Mod(r2, pk.N)

	C := new(big.Int).Set(r2)
	if b == 1 {
		// C = A * r^2 mod N
		C.Mul(C, pk.A)
		C.Mod(C, pk.N)
	}

	return &Commitment{C: C}, r, nil
}

// Open verifies the opening (b, r) against commitment C.
func Open(pk *PublicKey, com *Commitment, b int, r *big.Int) bool {
	if b != 0 && b != 1 {
		return false
	}
	// Check gcd(r, N) = 1
	one := big.NewInt(1)
	if new(big.Int).GCD(nil, nil, r, pk.N).Cmp(one) != 0 {
		return false
	}

	r2 := new(big.Int).Mul(r, r)
	r2.Mod(r2, pk.N)

	Ccheck := new(big.Int).Set(r2)
	if b == 1 {
		Ccheck.Mul(Ccheck, pk.A)
		Ccheck.Mod(Ccheck, pk.N)
	}

	return Ccheck.Cmp(com.C) == 0
}

func Main() {
	// Example usage (small bit length for demonstration purposes ONLY).
	// Use at least 2048 bits in any realistic setting.
	pk, sk, err := GenerateBlumModulus(512)
	if err != nil {
		log.Fatalf("Failed to generate modulus: %v", err)
	}

	fmt.Println("Public modulus N =", pk.N)
	fmt.Println("Public A =", pk.A)
	fmt.Println("Secret p =", sk.P)
	fmt.Println("Secret q =", sk.Q)

	// Commit to bit b
	b := 1
	com, r, err := Commit(pk, b)
	if err != nil {
		log.Fatalf("Commit failed: %v", err)
	}

	fmt.Printf("Committed bit %d\n", b)
	fmt.Println("Commitment C =", com.C)
	fmt.Println("Randomness r =", r)

	// Verify opening
	ok := Open(pk, com, b, r)
	fmt.Println("Open with correct bit and r ->", ok)

	// Try to cheat with wrong bit
	ok = Open(pk, com, 1-b, r)
	fmt.Println("Open with wrong bit and same r ->", ok)
}
