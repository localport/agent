package service

import (
	"strconv"
	"testing"
)

func TestFreeSystemID(t *testing.T) {
	uids := "root 0\n_www 70\ntaken 400\n"
	gids := "wheel 0\ngroup401 401\nmalformed\n"
	if id, err := freeSystemID(uids, gids); err != nil || id != 402 {
		t.Fatalf("freeSystemID = %d, %v, want 402", id, err)
	}
	var all string
	for id := accountIDFirst; id < accountIDLimit; id++ {
		all += "u " + strconv.Itoa(id) + "\n"
	}
	if _, err := freeSystemID(all, ""); err == nil {
		t.Fatal("freeSystemID found an id with every one taken")
	}
}
