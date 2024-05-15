package main

import (
	"fmt"
	"net/http"
	"runtime"
)

func main() {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")

		url := fmt.Sprintf("<h1>%s://%s%s</h1>\n", r.URL.Scheme, r.Host, r.URL.Path)

		fmt.Fprintf(w, "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
        fmt.Fprintf(w, "<meta charset=\"UTF-8\">\n<title>Docker Hosted Website</title>\n</head>\n<body>\n")
        fmt.Fprintf(w, "<h1>Running on %s</h1>\n", runtime.GOOS)
		fmt.Fprintf(w, url)

		
	}

	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}