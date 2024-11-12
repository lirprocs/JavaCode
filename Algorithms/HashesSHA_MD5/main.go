package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// hashPasswordSHA256 принимает пароль и возвращает его хеш SHA-256
func hashPasswordSHA256(password string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

// hashPasswordMD5 принимает пароль и возвращает его хеш MD5
func hashPasswordMD5(password string) string {
	hasher := md5.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

func main() {
	password := "verysecretpassword"

	fmt.Println("Hashing with SHA-256:")
	fmt.Println(hashPasswordSHA256(password))

	fmt.Println("Hashing with MD5 (not recommended):")
	fmt.Println(hashPasswordMD5(password))
}

/*
	Уязвимости MD5:
		1) Уязвимость к коллизиям
		2) 128 битное хэш-значение
*/
