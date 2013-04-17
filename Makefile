init:  
	./bin/go get code.google.com/p/go.crypto/ssh
	./bin/go install

certs:
	mkdir -p certs/
	@echo "Do not use a passphrase for temporary certs"
	ssh-keygen -t rsa -f certs/server.key
	@echo "Temporary certs have been setup in certs/ directory"

test-certs:
	mkdir -p fixture/
	openssl genrsa -out fixture/server-key.pem
	openssl req -new -key fixture/server-key.pem -out fixture/server-csr.pem
	openssl x509 -req -in fixture/server-csr.pem -signkey fixture/server-key.pem -out fixture/server-cert.pem

test:
	APISERVER_KEY="SUPER KEY" ./bin/go test
