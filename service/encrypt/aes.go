package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

func PKCS5Padding(cipherText []byte, blockSize int) []byte {
	if blockSize == 0 {
		return []byte("")
	}
	padding := blockSize - len(cipherText)%blockSize
	paddingText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, paddingText...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 padding 次
	padding := int(origData[length-1])
	return origData[:(length - padding)]
}

func Decrypt(cipherText, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	srcLen := len(cipherText)
	if srcLen%block.BlockSize() != 0 {
		return "", errors.New("crypto/cipher: input not full blocks")
	}
	dst := make([]byte, srcLen)
	iv := make([]byte, 16)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, cipherText)
	return string(PKCS5UnPadding(dst)), nil
}

func Encrypt(src, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	src = PKCS5Padding(src, block.BlockSize())
	srcLen := len(src)
	if srcLen%block.BlockSize() != 0 {
		return nil, errors.New("need a multiple of the blockSize")
	}
	dst := make([]byte, srcLen)
	iv := make([]byte, 16)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(dst, src)
	return dst, nil
}
