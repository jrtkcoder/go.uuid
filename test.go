package main

import (
	"fmt"

	//"github.com/zhenorzz/snowflake"
	"github.com/satori/go.uuid"
)

func main() {

	/*
    // Create a new Node with a Node number of 1
    sf, err := snowflake.New(1)
    if err != nil {
        panic(err)
    }

    // Generate a snowflake ID.
    uuid1, err := sf.Generate()
	
    // Print
    fmt.Println(uuid1)
	*/
	
	//
	//timeUUID, _ := uuid.NewV4()
	//fmt.Println(timeUUID)
	
	
	//递增uuid
	u0 := uuid.NewIncUUID("aabbccdd")
	fmt.Printf("UUIDv0: %s\n", u0)
	
	//u0.Bytes()转换成字节字符串
	for _,n := range(u0.Bytes()) {
        fmt.Printf("%02x",n)
    }
	fmt.Printf("\n")
	
	/*
	u1 := uuid.NewV1()
	fmt.Printf("UUIDv1: %s\n", u1)
	
	
	
	u4 := uuid.NewV4()
	fmt.Printf("UUIDv4: %s\n", u4)
	
	u5 := uuid.NewV5(uuid.NamespaceDNS, "aabbccdd")
	fmt.Printf("UUIDv5: %s\n", u5)

	// Parsing UUID from string input
	
	u2, err := uuid.FromString("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if err != nil {
		fmt.Printf("Something gone wrong: %s\n", err)
	}
	*/
	//fmt.Printf("Successfully parsed: %s\n", u2)
	
	
}