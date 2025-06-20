package model

type WebResponse struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data"`
}
