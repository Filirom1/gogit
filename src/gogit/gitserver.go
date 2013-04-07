package gogit

import (
	"crypto/tls"
	b64 "encoding/base64"
	json "encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"code.google.com/p/go.crypto/ssh"
)

func getOrDefault(str, defaultValue string) string {
	if str == "" {
		return defaultValue
	}
	return str
}

var (
	GITMOUTH_PORT               = getOrDefault(os.Getenv("GITMOUTH_PORT"), "2222")
	GITMOUTH_PRIVATE_KEY        = getOrDefault(os.Getenv("GITMOUTH_PRIVATE_KEY"), "../../certs/server.key")
	GITMOUTH_PUBLIC_KEY         = getOrDefault(os.Getenv("GITMOUTH_PUBLIC_KEY"), "../../certs/server.key.pub")
	DYNOHOST_RENDEZVOUS_PORT    = getOrDefault(os.Getenv("DYNOHOST_RENDEZVOUS_PORT"), "4000")
	APISERVER_PROTOCOL          = getOrDefault(os.Getenv("APISERVER_PROTOCOL"), "https")
	APISERVER_HOSTNAME          = getOrDefault(os.Getenv("APISERVER_HOSTNAME"), "localhost")
	APISERVER_PORT              = getOrDefault(os.Getenv("APISERVER_PORT"), "5000")
	APISERVER_KEY               = os.Getenv("APISERVER_KEY")

	appNameRegexp = regexp.MustCompile(`^'/*(?P<app_name>[a-zA-Z0-9][a-zA-Z0-9@_-]*).git'$`)

  tr = &http.Transport{
    TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
  }
	client        = &http.Client{Transport: tr}
)

func main() {
  StartGitServer()
}

func StartGitServer() {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(cnn *ssh.ServerConn, user, algo string, pubkey []byte) bool {
			// find a user matching the public key
			fingerprint := b64.StdEncoding.EncodeToString(pubkey)
			url := APISERVER_PROTOCOL + `://` + APISERVER_HOSTNAME + `:` + APISERVER_PORT + `/internal/lookupUserByPublicKey?fingerprint=` + url.QueryEscape(fingerprint)

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				log.Println("Unable to build request")
				return false
			}
			req.SetBasicAuth("", APISERVER_KEY)

			log.Printf("Checking fingerprint %v ", url)
			resp, err := client.Do(req)
			if err != nil {
        log.Fatal("Unable to contact api server ", err)
				return false
			}
			defer resp.Body.Close()
			Body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatal("Unable to parse body ", err)
				return false
			}
			if resp.StatusCode != 200 {
				log.Printf("Key auth failed for %+v because %+v", fingerprint, string(Body))
				return false
			}
			apiKey := string(Body)
			cnn.User = apiKey
			log.Println("User API key is " + cnn.User)

			return true
		},
	}

	pemBytes, err := ioutil.ReadFile(GITMOUTH_PRIVATE_KEY)
	if err != nil {
		log.Fatal("Failed to load private key:", err)
	}
	if err = config.SetRSAPrivateKey(pemBytes); err != nil {
		log.Fatal("Failed to parse private key:", err)
	}

	// Once a ServerConfig has been configured, connections can be
	// accepted.
  log.Println("Git Server Listen on " + GITMOUTH_PORT)
	listener, err := ssh.Listen("tcp", "0.0.0.0:" + GITMOUTH_PORT, config)
	if err != nil {
		log.Fatal("failed to listen for connection")
	}
  go func(){
    for {
      // A ServerConn multiplexes several channels, which must 
      // themselves be Accepted.
      log.Println("Git Server accept connection")
      sConn, err := listener.Accept()
      if err != nil {
        log.Fatal("failed to accept incoming connection")
        continue
      }
      if err := sConn.Handshake(); err != nil {
        log.Fatal("failed to handshake")
        continue
      }
      go handleServerConn(sConn)
    }
  }()
}

func handleServerConn(sConn *ssh.ServerConn) {
	defer sConn.Close()
	for {
		// Accept reads from the connection, demultiplexes packets
		// to their corresponding channels and returns when a new
		// channel request is seen. Some goroutine must always be
		// calling Accept; otherwise no messages will be forwarded
		// to the channels.
		ch, err := sConn.Accept()
		log.Println("Git Server accept channel")
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Fatal("handleServerConn Accept:", err)
			break
		}
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "unknown channel type")
			break
		}
		go handleChannel(sConn.User, ch)
	}
}

// Ssh priv/pub key authentication successed and a channel of type "session" is initiated
func handleChannel(apiKey string, ch ssh.Channel) {
	ch.Accept()
  var channelRequest []byte
  _, err := ch.Read(channelRequest)
	if err == io.EOF {
		return
	}
  var cmd string
	if err != nil {
    switch maybeChannelRequest := err.(type){
      case ssh.ChannelRequest: 
        cmd = string(maybeChannelRequest.Payload)
      default:
        log.Fatal("handleChannel readLine err:", err)
        return
    }
	}
	defer ch.Close()

	returnPathError := func() {
		fmt.Fprintf(ch, `\n ! Invalid path.\n ! Syntax is: git@heroku.com:<app>.git where <app> is your app\'s name.\n\n`)
	}

  log.Printf("receive command %v", cmd)

	cmdParts := strings.Split(cmd, ` `)
	if len(cmdParts) != 2 {
		returnPathError()
		return
	}

	// git push ==> comand is git-receive-pack
	// git pull ==> comand is git-upload-pack
	gitCommand := cmdParts[0]
	if !strings.EqualFold(gitCommand,"git-receive-pack") && strings.EqualFold(gitCommand,"git-upload-pack") {
		returnPathError()
		return
	}

	// the git arguments contains the app name
	// for example: git-receive-pack 'serious-app.git', serious-app is the app name
	gitArgs := cmdParts[1]
	appName := appNameRegexp.FindStringSubmatch(gitArgs)[1]
	if appName == "" {
		returnPathError()
		return
	}

	// create a new temporary dyno to execute a git command
	url := APISERVER_PROTOCOL + `://` + APISERVER_HOSTNAME + `:` + APISERVER_PORT + `/internal/` + appName + `/gitaction?command=` + gitCommand
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		log.Fatal("Unable to build request", err)
		return
	}
	req.SetBasicAuth("", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Unable to contact build server", err)
		return
	}
	defer resp.Body.Close()
	Body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Unable to parse body", err)
		return
	}
	if resp.StatusCode != 200 {
		log.Fatal("Unable to contact build server ", string(Body))
		return
	}

	// parse the git action response
	type GitActionMsg struct {
    Host    string `json:"host"`    // dynohost hostname where the dyno is started
    Dyno_id string `json:"dyno_id"` // unique id for the dyno
    Rez_id  string `json:"rez_id"`  // TODO remove this unused field
	}

	var msg GitActionMsg
	err = json.Unmarshal(Body, &msg)
	if err != nil {
		log.Fatal("unable to parse "+string(Body), err)
		return
	}

	// connect to rendezvous, the dyno stdin/stdout-stderr stream hub
	adr := msg.Host + ":" + DYNOHOST_RENDEZVOUS_PORT
	conn, err := tls.Dial("tcp", adr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Fatal("unable to contact dynohost rendezvous "+adr, err)
		return
	}

	// Authenticate on rendezvous, and register the dyno
	fmt.Fprintf(conn, APISERVER_KEY+"\n"+msg.Dyno_id+"\n")

	// read everything from rendezvous connection and write to the ssh channel
	for {
		buf := make([]byte, 1024)
		_, err := conn.Read(buf)
		if err == io.EOF {
			continue
		}
		if err != nil {
			log.Fatal("Unable to read from dynohost rendezvous", err)
			return
		}
		_, err = ch.Write(buf)
		if err != nil {
			log.Fatal("Unable to write to ssh channel", err)
			return
		}
	}
}
