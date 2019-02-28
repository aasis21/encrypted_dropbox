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
    
    // GetUser (Try to ruin user data)
	aniketKey := assn1.GetUserKey("aniket", "password1")
	aniketCnt, _ := assn1.GetMapContent(aniketKey)
	// fmt.Println(aniketCnt)
	aniketCnt[len(aniketCnt)/2] = []byte("k")[0]
	assn1.SetMapContent(aniketKey, aniketCnt)

	user1, err = assn1.GetUser("aniket", "password1")
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(user1)
	}
}

