package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"log"
)

func main() {
	//key := []byte("1234567890abcdef")
	//cipher, err := sm4.NewCipher(key)
	//if err != nil {
	//	return
	//}

	priv, err := sm2.GenerateKey(rand.Reader) // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	msg := []byte("Tongji Fintech Research Institute")
	pub := &priv.PublicKey
	ciphertxt, err := pub.EncryptAsn1(msg, rand.Reader) //sm2加密
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("加密结果:%x\n", ciphertxt)
	plaintxt, err := priv.DecryptAsn1(ciphertxt) //sm2解密
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(msg, plaintxt) {
		log.Fatal("原文不匹配")
	}

	sign, err := priv.Sign(rand.Reader, msg, nil) //sm2签名
	if err != nil {
		log.Fatal(err)
	}
	isok := pub.Verify(msg, sign) //sm2验签
	fmt.Printf("Verified: %v\n", isok)

	data := "test"
	h := sm3.New()
	h.Write([]byte(data))
	sum := h.Sum(nil)
	fmt.Printf("digest value is: %x\n", sum)
}
