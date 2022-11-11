package main

import (
	as "github.com/aerospike/aerospike-client-go"
)

func addHash(hash string, seconds uint32) bool {

	key, _ := as.NewKey(namespace, setName, hash)
	bin := as.NewBin("F", 1)

	err := client.AddBins(as.NewWritePolicy(0, seconds), key, bin)

	return err != nil
}

func isSet(hash string) bool {

	key, _ := as.NewKey(namespace, setName, hash)

	_, err := client.Get(as.NewPolicy(), key)

	return err == nil
}
