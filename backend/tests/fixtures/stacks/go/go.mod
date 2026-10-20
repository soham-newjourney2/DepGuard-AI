module example.com/shop

go 1.21

require (
	github.com/gin-gonic/gin v1.9.0
	golang.org/x/net v0.10.0 // indirect
)

require github.com/old/lib v1.0.0

replace github.com/old/lib => github.com/new/lib v1.2.0
