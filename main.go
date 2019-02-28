package main

import (
    "fmt"
    "golang.org/x/crypto/argon2"
    "encoding/hex"
)


// Argon2:  Automatically choses a decent combination of iterations and memory
func Argon2Key(password []byte, salt []byte,keyLen uint32) []byte {
	
  return argon2.IDKey(password, salt,
		1,
		64*1024,
		4,
		keyLen)

}

func main() {
	fmt.Println("Hello, 世界")
    val1 := Argon2Key([]byte("Password"),[]byte("nosalt"),32)
    fmt.Println(hex.EncodeToString(val1))
}

