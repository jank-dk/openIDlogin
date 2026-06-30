package main

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
)

func ReadJson[T any](resp *http.Response) (T, error) {
	var result T
	var err error
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(os.Stdout, resp.Body)
		fmt.Println()
		return result, fmt.Errorf("received status code %d", resp.StatusCode)
	}

	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return result, fmt.Errorf("failed to decode mime type: %w", err)
	}
	if contentType != "application/json" {
		return result, fmt.Errorf("expected application/json content-type, but got %s", contentType)
	}

	dec := json.NewDecoder(resp.Body)

	err = dec.Decode(&result)
	return result, err
}
