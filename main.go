package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	bestScore  = 0
	targetByte byte
)

type Wallet struct {
	PrivateKey *ecdsa.PrivateKey
	Address    common.Address
	Score      int
}

func (w Wallet) String() string {
	return fmt.Sprintf("key: %s address: %s score: %d", hex.EncodeToString(crypto.FromECDSA(w.PrivateKey)), w.Address, w.Score)
}

var targetInt = flag.Int("b", 0, "target byte")

func main() {
	flag.Parse()
	targetByte = byte(*targetInt)

	recvCh := make(chan Wallet)
	for i := 0; i < runtime.NumCPU(); i++ {
		go genAndCheck(recvCh)
	}
	go func() {
		for w := range recvCh {
			fmt.Println(w.String())
		}
	}()

	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, os.Kill)
	sig := <-ch
	fmt.Println(sig.String())
}

func genAndCheck(ch chan Wallet) {
	c := crypto.S256()
	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		panic(err)
	}
	for {
		address := crypto.PubkeyToAddress(privateKey.PublicKey)
		score := scoreAddress(&address)
		if score > bestScore {
			bestScore = score
			ch <- Wallet{
				PrivateKey: privateKey,
				Address:    address,
				Score:      score,
			}
			privateKey = crypto.ToECDSAUnsafe(crypto.FromECDSAPub(&privateKey.PublicKey)[33:])
		} else {
			privateKey = increase(privateKey)
		}
	}
}

func increase(k *ecdsa.PrivateKey) *ecdsa.PrivateKey {
	b := crypto.FromECDSA(k)
	for i := len(b) - 1; i >= 0; i-- {
		v := b[i] + 1
		b[i] = v
		if v > 0 {
			break
		}
	}
	return crypto.ToECDSAUnsafe(b)
}

func scoreAddress(address *common.Address) int {
	score := 0
	for _, v := range address {
		if v == targetByte {
			score += 1
			continue
		}
		break
	}
	return score
}
