package main

import (
  "io/ioutil"
  "fmt"
  "log"
  "net/http"
)

var (
  hostname string
  port = "8080"
)


func serveID(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintf(w, hostname)
}

func startServer() {
  raw, err := ioutil.ReadFile("/etc/hostname")
  if err != nil {
    log.Fatal("Fail to read hostname")
  }
  hostname = string(raw)
  http.HandleFunc("/serverid", serveID)
  http.HandleFunc("/hello", serveID)
  log.Fatal(http.ListenAndServe("0.0.0.0:"+port, nil))
}


func main() {
    startServer()
}

