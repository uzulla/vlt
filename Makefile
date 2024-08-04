vlt:
	go mod tidy
	go build -o vlt ./main.go
	cp vlt vlt_`uname -o`-`uname -m`
