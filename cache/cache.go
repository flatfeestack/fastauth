//cgo and sqlite is terribly slow. Either we can use https://gitlab.com/cznic/sqlite
//or wait until its executed parallel: https://github.com/golang/go/issues/9887
//for now, we just cache it with the dependencies, which should not change too often
package main

import (
	_ "github.com/mattn/go-sqlite3"
)

func main() {}
