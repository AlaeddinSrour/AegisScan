package fixtures

import (
	"net/http"
	"os"
)

func fetchHealthcheck() (*http.Response, error) {
	return http.Get("https://status.example.com/health")
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
