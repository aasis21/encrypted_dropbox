package main

import (
    "fmt"
    "./assn1"
)

func main() {
	fmt.Println("Hello, 世界")
    // InitUser
	user1, err := assn1.InitUser("aniket", "password1")
	if err != nil {
		fmt.Println(err.Error())
	}

	user2, err := assn1.InitUser("ashish", "password2")
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println(user1, user2)
}

