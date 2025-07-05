package helper

import "net/http"

func WriteOAuthHTMLResponse(writer http.ResponseWriter, html string) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte(html))
}
