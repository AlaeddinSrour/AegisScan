package fixtures

import (
	"net/http"
	"os"
)

func fetchPreview(request *http.Request) (*http.Response, error) {
	target := request.URL.Query().Get("url")
	return http.Get(target)
}

func readExisting(path string) ([]byte, error) {
	if _, err := os.Stat(path); err == nil {
		return os.ReadFile(path)
	}
	return nil, os.ErrNotExist
}

func readAfterGuard(path string) ([]byte, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}
