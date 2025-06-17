package exception

import (
	"brightmart-backend/internal/helper"
	"fmt"
	"net/http"
)

func ErrorHandler(writer http.ResponseWriter, request *http.Request, err interface{}) {
	errorMap := map[string]string{}

	castErr, ok := err.(error)
	if ok {
		errorMap["internal"] = castErr.Error()
	} else {
		errorMap["internal"] = fmt.Errorf("%v", err).Error()
	}

	helper.WriteErrorResponse(writer, http.StatusInternalServerError, errorMap)
}
