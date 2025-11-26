package zad2

import (
	"crypto/rand"
	"list6/PerfectHiding"
	"math/big"
)

type Participant struct {
	message       string
	r             string
	memberMessage string
	memberR       string
}

func newParticipant(message, r string) *Participant {
	return &Participant{message: message, r: r}
}

func (p *Participant) draw() {
	res, _ := rand.Int(rand.Reader, big.NewInt(2))
	if res.Cmp(big.NewInt(0)) == 0 {
		p.message = "0"
	} else {
		p.message = "1"
	}
}

func (p *Participant) commit() *big.Int {
	return PerfectHiding.Commit(p.message, p.r)
}

func (p *Participant) loadMemberSecrets(secrets []string) {
	p.memberMessage = secrets[0]
	p.memberR = secrets[1]
}

func (p *Participant) check(commitment *big.Int) bool {
	return PerfectHiding.Unpack(p.memberMessage, p.memberR, commitment)
}

func stringXor(a, b string) string {
	if a == b {
		return "0"
	} else {
		return "1"
	}
}

func Zad2() string {
	aliceSecrets := []string{
		"0", "essa",
	}
	bobSecrets := []string{
		"1", "nice",
	}
	alice := newParticipant(aliceSecrets[0], aliceSecrets[1])
	bob := newParticipant(bobSecrets[0], bobSecrets[1])

	alice.draw()
	bob.draw()

	aliceSecrets[0] = alice.message
	bobSecrets[0] = bob.message

	aliceCommitment := alice.commit()
	bobCommitment := bob.commit()

	alice.loadMemberSecrets(bobSecrets)
	bob.loadMemberSecrets(aliceSecrets)

	if !alice.check(bobCommitment) {
		panic("bob commitment is invalid")
	}

	if !bob.check(aliceCommitment) {
		panic("alice commitment is invalid")
	}

	return stringXor(alice.message, bob.message)
}
