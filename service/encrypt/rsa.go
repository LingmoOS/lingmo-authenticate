package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type RsaPaddingType int

const (
	PKCS1     RsaPaddingType = 1 << 0
	NoPadding RsaPaddingType = 1 << 1
	OAPE      RsaPaddingType = 1 << 2
)

//加密算法类型
type AlgType int

const (
	AT_RSA AlgType = iota
)

var AlgTypes = []AlgType{
	AT_RSA,
}

type AsymCrypt interface {
	PubkeyInfo() (int, string)
	Type() AlgType
	Encrypt([]int, []byte) ([]byte, error)
	Decrypt([]int, []byte) ([]byte, error)
	SupportFlags([]int) ([]int, error)
}

type Rsa struct {
	flag          int
	privateKey    string
	publicKey     string
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
}

func init() {
}

func NewRsa(length int) (*Rsa, error) {
	var privateKey, publicKey string
	var block *pem.Block
	var err error

	prvKey, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		return nil, err
	}

	privateKey, publicKey, err = generatePKCS1PrivateKey(prvKey)
	if err != nil {
		return nil, err
	}

	var res []byte
	block, res = pem.Decode([]byte(publicKey))
	if len(res) != 0 {
		err = errors.New(string(res))
		return nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &Rsa{
		privateKey:    privateKey,
		publicKey:     publicKey,
		rsaPrivateKey: prvKey,
		rsaPublicKey:  pub.(*rsa.PublicKey),
	}, nil
}

func (r *Rsa) PublicKey() string {
	return r.publicKey
}

func (*Rsa) Type() AlgType {
	return AT_RSA
}

func (r *Rsa) PrintPublicKey() string {
	return fmt.Sprintf("prv: %v, pub: %v", r.rsaPrivateKey.PublicKey.N, r.rsaPublicKey.N)
}

func generatePKCS1PrivateKey(prvKey *rsa.PrivateKey) (string, string, error) {
	privateKey := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(prvKey),
	}))
	derPkix, err := x509.MarshalPKIXPublicKey(&prvKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	publicKey := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}))
	//fmt.Printf("create privateKey: %s, publicKey %s", privateKey, publicKey)
	return privateKey, publicKey, nil
}

func (r *Rsa) Encrypt(flags []int, data []byte) ([]byte, error) {
	switch RsaPaddingType(flags[0]) {
	case OAPE:
		break
	case NoPadding:
		break
	case PKCS1:
		break
	default:
		break
	}
	token, err := rsa.EncryptPKCS1v15(rand.Reader, r.rsaPublicKey, []byte(data))

	return token, err
}

func (r *Rsa) Decrypt(flags []int, data []byte) (token []byte, err error) {
	token, err = rsa.DecryptPKCS1v15(rand.Reader, r.rsaPrivateKey, []byte(data))
	//switch RsaPaddingType(flags[0]) {
	//case OAPE:
	//	break
	//case NoPadding:
	//	break
	//case PKCS1:
	//	token, err = rsa.DecryptPKCS1v15(rand.Reader, r.rsaPrivateKey, []byte(data))
	//	break
	//default:
	//	break
	//}

	return
}

func (r *Rsa) PrivateKey() string {
	return r.privateKey
}

func (r *Rsa) PubkeyInfo() (int, string) {
	return int(r.Type()), r.PublicKey()
}

func (r *Rsa) SupportFlags(flags []int) ([]int, error) {
	if len(flags) != 1 || flags[0] != int(PKCS1) {
		return []int{int(PKCS1)}, errors.New("error")
	}
	return flags, nil
}

func (r *Rsa) DefaultFlags() []int {
	return []int{int(PKCS1)}
}
