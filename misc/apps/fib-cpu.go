package main

import (
    "flag"
)
var count = flag.Int("n", 32, "loop count")


func fib(n int) int {
    if n<=1 {
        return n
    }
    return fib(n-1)+fib(n-2)
}
func main() {
    flag.Parse()
    fib(*count)
}
