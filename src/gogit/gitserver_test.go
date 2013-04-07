package gogit

import (
	"crypto/tls"
	"fmt"
	. "launchpad.net/gocheck"
	"log"
	"net"
  "bytes"
  "io"
	"net/http"
	"testing"
  "strings"
  "crypto"
  "crypto/rsa"
  "crypto/x509"
  "encoding/pem"
	"code.google.com/p/go.crypto/ssh"
)

var (
  privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAvvBwbFBwdwCpxVabvto1SNbZwFjk13aWkfRMts9Sm5fpYN4G
xk/eelD6iSY8NnsqgkziOStxC73BoJZvKcU9D6tNRcpZhKplC61Oi7JUmxOuHls2
vYPJfhmQuJfAg9pgZrn2/glnQgySyMBBUkLi09PlgFb92zTVTfPvzQi/o2MjpZ/U
am/UYmPbb28f7yAmn04cYhkYxfWNdFfg9G7ovvdAQIJC7k4OVwfh9fyl7chIWvaD
x8VlRD+b/jfX5opbQi5cYfR6mvjS4uqUdlO0Vkgu/ZXCP2691ofJppsIO5yvusHA
Fuy+qa6RY3rDfIAdnSb5gBh+CXSjUCTnkkuBIwIDAQABAoIBACzJINWHGJoRIcET
y3w8mnr3SiP/tc2EF1UsxEGs52dvfmImMdiaK0jtbZZ1zXHJ+fKOLhHSyrVCUQRl
xLU7elMOjxVrnQutG/5dLCtALPAi8ZhVNMXG/6AARx3FGnbS5gGyZOi5M+seH9/O
mIO/BI1DCnXL8cdU4SNjsD+babfcxRs9LZKMYnvoGRG/ZSAAYQlhMPZ73VJe/Ezs
mvwD8o9yFW5H/a5wWkEZMnPcO8TNyDq3Mk/qGRABaiR09UF+FsRgE4ombjCRY9pw
uHXfA6rGp8YoRdsKcLh33f6Jo+F87Ry0lImR5WIireJkODMnd1daP3iOSPYCVxCL
Co0ou+ECgYEA7w1J4cOvR5yzgA4XoAP9V+7VW/dS/aJEIxp7GOCStQzV163oqYGM
NxJyvkLUXmVG0qvrur0vOHGk2rlDrHbxQtbuFbZ4njuMrUpTkaO5ECJwSUy+tqWK
AuBV+tEtOjxAFx22HfDirYmWm2n3b3H8kK/U+PdkF5b/IOF89/D8t00CgYEAzHnr
4kTLymLKL+qxg8rNhfvGlcoE3DfONw8sHv/TsvCasvmhD48HpDeJBefOBdV8g1Tb
AWmBcRFQcaI6r6AJq3aHONfzGGjBaBSM1lj5eZsfu2CAg0Cf/O2oeWTKKKyt9Lbd
HZ3FmsAq4Qoyv4A6O5w5TsJuKcGb3JSXXTU0Qi8CgYEAuXnlBi9Pc0/JEiVc/UG7
MpvTnXyDPtnE5juooP+1tJYV4TdFGyexxBUjRC4UGn2X+uN7jjM1TSUX1MEEGe9b
eBHNPrmKUrM/jkDqIEkY0MT3vFe4bXx5XYv0Chx8a//NdmIOKKL7LcxgN4t7eVPG
s/hJVTaVyZvVrgxmavXnDs0CgYEAuvBMY5UZ63Hd/2jF2gOzWmcQ6yjCwMKUWWoZ
oE2rMdEe3bmzMhJFnjDXqPqANH01VKxjfSsEGGcH8Juso5vgu02l2qYzrYE4MPt4
tw6pJjBYFmrnkxemLQrqF/G5kO4uK6hzBvyTCCPgD9XPB50noA/3pLXFGY/T+xou
OBzIJikCgYEAvf1nSWYpngGYNEeYQMthfQQ2e1vkaKwIGqDbCj0PfJqdtBn6FL9W
YTrz4A2jtBv8ZoJA7X9aUzvigj+EHwZzQJvseTopngF0TTqUxM2L03eV75jcn0vO
hE7VLpiZwTczHoFOdt/ek9kgj7SxxuOK1eaUUDhP0xn5bweL6slkPoE=
-----END RSA PRIVATE KEY-----`

  publicKey = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC+8HBsUHB3AKnFVpu+2jVI1tnAWOTXdpaR9Ey2z1Kbl+lg3gbGT956UPqJJjw2eyqCTOI5K3ELvcGglm8pxT0Pq01FylmEqmULrU6LslSbE64eWza9g8l+GZC4l8CD2mBmufb+CWdCDJLIwEFSQuLT0+WAVv3bNNVN8+/NCL+jYyOln9Rqb9RiY9tvbx/vICafThxiGRjF9Y10V+D0bui+90BAgkLuTg5XB+H1/KXtyEha9oPHxWVEP5v+N9fmiltCLlxh9Hqa+NLi6pR2U7RWSC79lcI/br3Wh8mmmwg7nK+6wcAW7L6prpFjesN8gB2dJvmAGH4JdKNQJOeSS4Ej"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type MySuite struct {
	apiListener        net.Listener
	rendezvousListener net.Listener
  tlsConfig          *tls.Config
}

func (s *MySuite) SetUpSuite(c *C) {
  cert, err := tls.LoadX509KeyPair("../../certs/server-cert.pem", "../../certs/server-key.pem")
  if err != nil {
    panic(err)
  }

  s.tlsConfig = &tls.Config{
    Certificates: []tls.Certificate{cert},
  }

  StartGitServer()
	s.startApiServer(c)
	s.startDynohostRendezvous(c)
}


func (s *MySuite) startApiServer(c *C) {
	http.HandleFunc("/internal/lookupUserByPublicKey", func(w http.ResponseWriter, r *http.Request) {
		fingerprint := r.FormValue("fingerprint")
		if fingerprint != publicKey {
			http.Error(w, "Not allowed", 405)
      return
		}
		fmt.Fprintf(w, "1234")
	})

	http.HandleFunc("/internal/myapp/gitaction", func(w http.ResponseWriter, r *http.Request) {
		// check basic auth ':1234' encoded in base64 
    log.Printf(r.Header.Get("Authorization"))
		if !strings.EqualFold(r.Header.Get("Authorization"), "Basic OjEyMzQ=") {
			http.Error(w, "Unauthorized", 401)
      return
		}
		fmt.Fprintf(w, `{"host": "localhost", "dyno_id": "dyno_id", "rez_id": "not-used"}`)
	})

	log.Println("Mock ApiServer listen on 5000")
	l, err := tls.Listen("tcp", ":5000", s.tlsConfig)

	if err != nil {
		panic(err)
	}

	// Keep listener around such that test teardown can close it
	s.apiListener = l

	go func() {
    log.Println("Mock ApiServer serve resources")
		err := http.Serve(l, nil)
		if err != nil {
			panic(err)
		}
	}()
}

func (s *MySuite) startDynohostRendezvous(c *C) {
	log.Println("Mock Dynohost Rendezvous listen on 4000")
	l, err := tls.Listen("tcp", ":4000", s.tlsConfig)
	if err != nil {
		panic(err)
	}
	s.rendezvousListener = l

  go func(){
    for {
      log.Println("Mock Dynohost Rendezvous accept connection")
      conn, err := l.Accept()
      if err != nil {
        panic(err)
      }
      defer conn.Close()
      go func() {
        defer conn.Close()
        fmt.Fprintf(conn, `Message from rendezvous`)
      }()
    }
  }()
}

func (s *MySuite) TearDownSuite(c *C) {
	s.stopApiServer(c)
	s.stopDynohostRendezvous(c)
}

func (s *MySuite) stopApiServer(c *C) {
	s.apiListener.Close()
}

func (s *MySuite) stopDynohostRendezvous(c *C) {
	s.rendezvousListener.Close()
}


var _ = Suite(&MySuite{})

type keychain struct {
  key *rsa.PrivateKey
}

 
func (k *keychain) Sign(i int, rand io.Reader, data []byte) (sig []byte, err error) {
  hashFunc := crypto.SHA1
  h := hashFunc.New()
  h.Write(data)
  digest := h.Sum(nil)
  return rsa.SignPKCS1v15(rand, k.key, hashFunc, digest)
}


func (k *keychain) Key(i int) (interface{}, error) {
  if i != 0 {
    return nil, nil
  }
  return &k.key.PublicKey, nil
}

func (s *MySuite) TestGoGitShouldAuthenticateAndProxySSHToRendezVous(c *C) {
  block, rest := pem.Decode([]byte(privateKey))
  if len(rest) > 0 {
    panic(`extra data ` + string(rest))
  }
  rsakey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
  if err != nil {
    panic(err)
  }
  clientKey := &keychain{rsakey}

  clientConfig := &ssh.ClientConfig{
    User: "wuhao",
    Auth: []ssh.ClientAuth{
      ssh.ClientAuthKeyring(clientKey),
    },
  }
  client, err := ssh.Dial("tcp", "127.0.0.1:2222", clientConfig)
  if err != nil {
    panic("Failed to dial: " + err.Error())
  }
  session, err := client.NewSession()
  if err != nil {
    panic("Failed to create session: " + err.Error())
  }
  defer session.Close()

  var b bytes.Buffer
  session.Stdout = &b

  err = session.Run(`git-receive-pack 'myapp.git'`)
  if err == io.EOF {
    return
  }
  if err != nil {
    panic(err)
  }
  fmt.Println(b.String())

}
