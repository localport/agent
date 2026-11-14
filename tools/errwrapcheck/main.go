// Command errwrapcheck is a go vet tool that reports format text around a
// coded error (see Analyzer). `make lint` runs it:
//
//	go vet -vettool=<path to errwrapcheck> ./...
package main

import "golang.org/x/tools/go/analysis/unitchecker"

func main() { unitchecker.Main(Analyzer) }
