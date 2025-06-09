package config

import "github.com/julienschmidt/httprouter"

func NewHttpRouter() *httprouter.Router {
	router := httprouter.New()

	return router
}
