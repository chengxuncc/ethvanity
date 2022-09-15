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
			fmt.Println("privatekey:", hex.EncodeToString(crypto.FromECDSA(w.PrivateKey)), "address:", w.Address, "score:", w.Score)
		}
	}()

	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, os.Kill)
	sig := <-ch
	fmt.Println(sig.String())
}

func genAndCheck(ch chan Wallet) {
	c := crypto.S256()
	for {
		privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			panic(err)
		}
		address := crypto.PubkeyToAddress(privateKey.PublicKey)
		score := scoreAddress(&address)
		if score > bestScore {
			bestScore = score
			ch <- Wallet{
				PrivateKey: privateKey,
				Address:    address,
				Score:      score,
			}
		}
	}
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
