# ttls
small lib thats creating temporary TLS listener with random server certificate.

why temporary ?
every time that `NewTTLSListener` get called , new TLS certificates will be created.

WARNING - Do Not Use For any project that requires MITM protection, more useful for some temporary cases with local AUTH.. 

## Installation
``` 
$ go get -u github.com/yaronsumel/ttls 
```

## Usage 

create the TLS Listener with Min effort
``` go
	server, _ := ttls.NewTTLSListener("0.0.0.0:8080", nil)
```
or customize the x509 certificate as you wish
``` go
	server, _ := ttls.NewTTLSListener("0.0.0.0:8080", &ttls.X509Opts{
		Country:"US",
		Organization:"GITHUB",
		SerialNumber:12345,
		SubjectKeyId:"somekeyid",
	})
```

all together 
``` go

server, _ := ttls.NewTTLSListener("0.0.0.0:8080", nil)

	for {
		conn, err := server.Listener.Accept()
		if err != nil {
		// something went wrong...
		}
		defer conn.Close()
		// do something with the client conn
	}
  ```
