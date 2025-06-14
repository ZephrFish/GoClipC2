# GoClipC2
Clipboard for Command and Control between VDI, RDP and Others on Windows

## Quick Start
```
git clone https://github.com/ZephrFish/GoClipC2
cd GoClipC2
go mod init clipboard-c2
go mod tidy
```
## Building The Client and Server
The following commands can be executed to build the client in exe format for execution on Windows:
```
# Build the server
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o server.exe server-coff.go

# Build the client
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o client.exe client-coff.go

# Build GUI-less client
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o client-stealth.exe client-coff.go
```

## Features

## Help

## Further Reading
I wrote a blog post([can be found here](blog.zsec.uk/clippy-goes-rogue/)) to acompany this tooling but have also released [ChunkyIngress](https://github.com/ZephrFish/ChunkyIngress) previously which might also interest you!
