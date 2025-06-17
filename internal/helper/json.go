package helper

import (
	"brightmart-backend/internal/model"
	"github.com/bytedance/sonic"
	"io"
	"net/http"
)

func ReadFromRequestBody(request *http.Request, result interface{}) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		PanicIfError(err)
	}

	err = sonic.Unmarshal(body, result)
	PanicIfError(err)
}

func WriteSuccessResponse(writer http.ResponseWriter, response interface{}) {
	webResponse := model.WebResponse{
		Status: http.StatusText(http.StatusOK),
		Data:   response,
	}

	jsonData, err := sonic.Marshal(webResponse)
	PanicIfError(err)

	_, err = writer.Write(jsonData)
	PanicIfError(err)
}

func WriteSuccessResponseNoData(writer http.ResponseWriter) {
	webResponse := model.WebResponse{
		Status: http.StatusText(http.StatusOK),
	}

	jsonData, err := sonic.Marshal(webResponse)
	PanicIfError(err)

	_, err = writer.Write(jsonData)
	PanicIfError(err)
}

func WriteErrorResponse(writer http.ResponseWriter, statusCode int, errorMap map[string]string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)

	webResponse := model.WebResponse{
		Status: http.StatusText(statusCode),
		Data:   errorMap,
	}

	jsonData, err := sonic.Marshal(webResponse)
	PanicIfError(err)

	_, err = writer.Write(jsonData)
	PanicIfError(err)
}
