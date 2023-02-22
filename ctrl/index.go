package ctrl

import (
	"net/http"

	. "github.com/mickael-kerjean/webpty/common"
)

func Main(res http.ResponseWriter, req *http.Request) {
	Middleware(func(res http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/socket" {
			HandleSocket(res, req)
			return
		} else if req.Method == "GET" {
			HandleStatic(res, req)
			return
		} else if req.URL.Path == "/" {
			return
		}
		ErrorPage(res, ErrNotFound, 404)
		return
	})(res, req)
}
