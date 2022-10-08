package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
    "flag"
    "strings"
    "time"
)

var url = flag.String("url", "", "target server")
var count = flag.Int("n", 128, "loop count")
func main() {
    flag.Parse()
    if *url == "" {
        log.Fatal("server empty")
    }
    ss := make(map[string]int)
    tr := http.Transport{ DisableKeepAlives: true }
    for i:=0; i<*count; i++ {
        c := http.Client{Timeout: time.Second, Transport: &tr}
        res, err := c.Get(*url)
        if err != nil {
            log.Fatal(err)
        }
        body, err := io.ReadAll(res.Body)
        res.Body.Close()
        if res.StatusCode !=200 {
            log.Fatalf("Response failed with status code: %d and\nbody: %s\n", res.StatusCode, body)
        }
        if err != nil {
            log.Fatal(err)
        }
        ss[strings.Trim(string(body), " \r\t\n")]+=1
        c.CloseIdleConnections()
    }
    for s, c := range(ss) {
        fmt.Println(s, c)
    }
}
