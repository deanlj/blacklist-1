package main

import (
	"log"
	"os"

	"github.com/thomas-marcucci/blacklist"
)

func main() {
	arguments := os.Args[1:]

	log.Println(arguments)

	if len(arguments) > 0 {
		blacklist.Check(arguments...)
	} else {
		log.Fatal("No arguments provided")
	}
}
