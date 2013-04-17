# GoGit - SSH-to-Git Server for Openruko

This is a experimental port of [gitmouth](https://raw.github.com/openruko/gitmouth) written in go.

## Introduction

`gogit` is a small SSH server written in Go using the 
[crypto ssh](http://godoc.org/code.google.com/p/go.crypto/ssh) framework to handle git push and pull
commands users make to manage their remote git repositories. It authenticates
the user by matching their public key fingerprint against the API server
database, then asks the API server to provision a dyno (a virtualization
container) with the respective git repository mounted, finally it connects to
this dyno over an SSH-like protocol and runs the git-receive-pack or git-
upload-pack command, which in turn will execute the buildpack via git hooks.

For those not familiar with Heroku infrastructure, as buildpacks can contain
potentially dangerous code the git command has to run inside an isolated dyno
too, hence gogit is simply a bridge from the ssh transport to where the git
commands run inside a dyno, authenticating and authorizing the request in the
pipeline.

## Requirements

Tested on Linux 3.8 using Go 1.0.3

On Archlinux:

    $ pacman -S go

TODO: Ubuntu 12.04 LTS


## Installation

    $ git clone https://github.com/Filirom1/gogit.git
    $ cd gogit
    $ make init # Installing dependencies
    $ make certs # Setting up temporary openssl certs

## Environment Variables

`gogit` will check for the presence of several environment variables, these
must be configured as part of the process start - e.g. configured in
supervisord or as part of boot script see `./bin/gogit`

* APISERVER_KEY - special key to authenticate with API server. Example:
  `APISERVER_KEY=abcdef-342131-123123123-asdasd`

## Tests

    make test-certs
    make test

It should prints something like this:

    APISERVER_KEY="SUPER KEY" ./bin/go test
    2013/04/17 09:21:42 Git Server Listen on 2222
    2013/04/17 09:21:42 Mock ApiServer listen on 5000
    2013/04/17 09:21:42 Git Server accept connection
    2013/04/17 09:21:42 Mock Dynohost Rendezvous listen on 4000
    2013/04/17 09:21:42 Mock ApiServer serve resources
    2013/04/17 09:21:42 Mock Dynohost Rendezvous accept connection
    2013/04/17 09:21:49 Checking fingerprint https://localhost:5000/internal/lookupUserByPublicKey?fingerprint=AAAAB3NzaC1yc2EAAAADAQABAAABAQC%2B8HBsUHB3AKnFVpu%2B2jVI1tnAWOTXdpaR9Ey2z1Kbl%2Blg3gbGT956UPqJJjw2eyqCTOI5K3ELvcGglm8pxT0Pq01FylmEqmULrU6LslSbE64eWza9g8l%2BGZC4l8CD2mBmufb%2BCWdCDJLIwEFSQuLT0%2BWAVv3bNNVN8%2B%2FNCL%2BjYyOln9Rqb9RiY9tvbx%2FvICafThxiGRjF9Y10V%2BD0bui%2B90BAgkLuTg5XB%2BH1%2FKXtyEha9oPHxWVEP5v%2BN9fmiltCLlxh9Hqa%2BNLi6pR2U7RWSC79lcI%2Fbr3Wh8mmmwg7nK%2B6wcAW7L6prpFjesN8gB2dJvmAGH4JdKNQJOeSS4Ej 
    2013/04/17 09:21:49 Git Server accept connection
    2013/04/17 09:21:49 Git Server accept channel
    2013/04/17 09:21:49 receive command git-receive-pack 'myapp.git'
    2013/04/17 09:21:49 Execute gitaction https://localhost:5000/internal/myapp/gitaction?command=git-receive-pack
    2013/04/17 09:21:49 Connect to Dynohost Rendezvous localhost:4000
    2013/04/17 09:21:49 Mock Dynohost Rendezvous accept connection
    2013/04/17 09:21:49 after run
    2013/04/17 09:21:49 stdout: Success from rendezvous
    2013/04/17 09:21:49 stderr: fake error
    OK: 1 passed

## TODO

The crypto ssh library was patched. It should be possible to avoid this.


    diff -r 2e6f4675f294 ssh/server.go
    --- a/ssh/server.go	Tue Apr 02 10:41:35 2013 -0400
    +++ b/ssh/server.go	Wed Apr 17 09:33:19 2013 +0200
    @@ -92,7 +92,7 @@
      result     bool
     }
     
    -const maxCachedPubKeys = 16
    +const maxCachedPubKeys = 0
     
     // A ServerConn represents an incoming connection.
     type ServerConn struct {
    @@ -441,6 +441,7 @@
            if len(payload) > 0 {
              return ParseError{msgUserAuthRequest}
            }
    +        s.User = userAuthReq.User
            if s.testPubKey(userAuthReq.User, algo, pubKey) {
              okMsg := userAuthPubKeyOkMsg{
                Algo:   algo,
    @@ -484,7 +485,6 @@
            default:
              return errors.New("ssh: isAcceptableAlgo incorrect")
            }
    -				s.User = userAuthReq.User
            if s.testPubKey(userAuthReq.User, algo, pubKey) {
              break userAuthLoop
            }

## License

`gitmouth` and other `openruko` components are licensed under MIT.
[http://opensource.org/licenses/mit-license.php](http://opensource.org/licenses/mit-license.php)


## Authors

Filirom1

