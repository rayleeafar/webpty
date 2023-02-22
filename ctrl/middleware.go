package ctrl

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	. "github.com/mickael-kerjean/webpty/common"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/ssh"
)

var (
	AuthTmpCache *cache.Cache
	EncryptKey   string
)

func init() {
	AuthTmpCache = cache.New(60*time.Minute, 65*time.Minute)

	go randomEncryptKey()
}

func Middleware(fn func(res http.ResponseWriter, req *http.Request)) func(res http.ResponseWriter, req *http.Request) {
	// tmpCache := cache.New(5*time.Minute, 10*time.Minute)
	return func(res http.ResponseWriter, req *http.Request) {
		startTime := time.Now()
		if strings.HasPrefix(req.URL.Path, "/app/") {
			HandleStatic(res, req)
			return
		}
		// username, password, ok := req.BasicAuth()
		username, password, keyfile := handlePasswdKeyFileAuth(req)
		Log.Info("user:%s, pass:%s, key:%s \n", username, password, keyfile)
		defer func() {
			Log.Info(
				"HTTP %.1fms %s %s",
				float32(time.Now().Sub(startTime).Microseconds())/1000,
				func() string {
					if username == "" {
						return "anonymous"
					}
					return username
				}(),
				req.URL.Path,
			)
		}()
		if password == "" && keyfile == "" {
			Log.Error("basic authentication error")
			// res.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			// ErrorPage(res, ErrNotAuthorized, http.StatusUnauthorized)
			// http.Redirect(res, req, "/login", 303)
			HandlerLogin(res, req)
			return
		}
		if _, found := AuthTmpCache.Get(username + ":" + password); found == false {
			var err error = nil
			// if username != "test" || password != "test" {
			// 	ErrorPage(res, ErrNotAuthorized, http.StatusUnauthorized)
			// 	err = ErrNotAuthorized
			// 	return
			// }
			sshPort := func() int {
				p := 22
				file, err := os.OpenFile("/etc/ssh/sshd_config", os.O_RDONLY, os.ModePerm)
				if err != nil {
					return p
				}
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					prefix := "Port"
					if strings.HasPrefix(line, prefix) {
						n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
						if err != nil {
							Log.Error("sshd cannot parse port from /etc/ssh/sshd_config")
						}
						p = n
						break
					}
				}
				file.Close()
				return p
			}()

			authConf := []ssh.AuthMethod{ssh.Password(password)}
			if keyfile != "" {
				pkey, err := ioutil.ReadFile(keyfile)
				if err != nil {
					Log.Error("Reading private key file failed: %s", err.Error())
					// res.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
					// ErrorPage(res, ErrNotAuthorized, http.StatusUnauthorized)
					// http.Redirect(res, req, "/login", 303)
					HandlerLogin(res, req)
					return
				}
				// create signer
				signer, err := ssh.ParsePrivateKey(pkey)
				if err != nil {
					Log.Error("Signer private key failed: %s", err.Error())
					// res.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
					// ErrorPage(res, ErrNotAuthorized, http.StatusUnauthorized)
					// http.Redirect(res, req, "/login", 303)
					HandlerLogin(res, req)
					return
				}
				authConf = []ssh.AuthMethod{ssh.PublicKeys(signer)}
			}

			client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), &ssh.ClientConfig{
				User: username,
				Auth: authConf,
				HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
					return nil
				},
			})
			if err != nil {
				Log.Error("sshd authentication error: %s", err.Error())
				// res.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
				// ErrorPage(res, ErrNotAuthorized, http.StatusUnauthorized)
				// http.Redirect(res, req, "/login", 303)
				HandlerLogin(res, req)
				return
			}
			client.Close()
			tokenStr := username + ":" + RandomString(8)
			AuthTmpCache.Set(tokenStr, nil, cache.DefaultExpiration)
			encTokenStr := encrypt(tokenStr, EncryptKey)

			res.Header().Set("Authorization", "Basic "+encTokenStr)
			res.Header().Set("xtoken", encTokenStr)
			res.WriteHeader(200)

			Log.Info("Authorization: %s", "Basic "+encTokenStr)
		}
		fn(res, req)
	}
}

func getCookieValByKey(r *http.Request, ckey string) string {
	if tokenCookie, err := r.Cookie(ckey); err == nil {
		return tokenCookie.Value
	}
	return ""
}
func handlePasswdKeyFileAuth(r *http.Request) (string, string, string) {

	hTokenStr, uTokenStr := getCookieValByKey(r, "xtoken"), r.URL.Query().Get("xtoken")
	Log.Info("Form:%#v,Header auth:%#v,Url auth:%s", r.Form.Get("user"), hTokenStr, uTokenStr)

	if len(hTokenStr) > 10 || len(uTokenStr) > 10 {
		authTokenStr := hTokenStr
		if len(authTokenStr) < 10 {
			authTokenStr = uTokenStr
		}
		decTokenStr := decrypt(authTokenStr, EncryptKey)
		if decUserPassArr := strings.Split(decTokenStr, ":"); len(decUserPassArr) == 2 {
			return decUserPassArr[0], decUserPassArr[1], ""
		}
		return "", "", ""
	}

	r.ParseMultipartForm(100)
	mForm := r.MultipartForm
	localKeyFileName := ""
	if mForm != nil {
		for k, _ := range mForm.File {
			// k is the key of file part
			file, fileHeader, err := r.FormFile(k)
			if err != nil {
				fmt.Println("inovke FormFile error:", err)
				break
			}
			defer file.Close()
			Log.Info("the uploaded file: name[%s], size[%d], header[%#v]",
				fileHeader.Filename, fileHeader.Size, fileHeader.Header)

			// store uploaded file into local path
			localKeyFileName = "/tmp/" + RandomString(8) + ".key"
			out, err := os.Create(localKeyFileName)
			if err != nil {
				fmt.Printf("failed to open the file %s for writing", localKeyFileName)
				break
			}
			defer out.Close()
			_, err = io.Copy(out, file)
			if err != nil {
				fmt.Printf("copy file err:%s\n", err)
				break
			}
			fmt.Printf("file %s uploaded ok\n", fileHeader.Filename)
		}
	}
	return r.Form.Get("user"), r.Form.Get("pass"), localKeyFileName
}

func randomEncryptKey() {

	for {
		bytes := make([]byte, 32) //generate a random 32 byte key for AES-256
		if _, err := rand.Read(bytes); err != nil {
			bytes = []byte(RandomString(32))
		}
		EncryptKey = hex.EncodeToString(bytes)
		// EncryptKey = RandomString(32)
		fmt.Printf("key to encrypt/decrypt : %s\n", EncryptKey)
		time.Sleep(time.Duration(12) * time.Hour)
	}

}

func encrypt(stringToEncrypt string, keyString string) (encryptedString string) {

	//Since the key is in string, we need to convert decode it to bytes
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		Log.Error("encrypt NewCipher error:%#v", err.Error())
		return ""
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		Log.Error("encrypt NewGCM error:%#v", err.Error())
		return ""
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		Log.Error("encrypt NonceSize error:%#v", err.Error())
		return ""
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	// return fmt.Sprintf("%s",ciphertext)
	return hex.EncodeToString(ciphertext)
}

func decrypt(encryptedString string, keyString string) (decryptedString string) {

	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		Log.Error("decrypt NewCipher error:%#v", err.Error())
		return ""
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		Log.Error("decrypt NewGCM error:%#v", err.Error())
		return ""
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()
	if len(enc) < nonceSize {
		Log.Error("decrypt encryptedString error!")
		return ""
	}
	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		Log.Error("decrypt out error:%#v", err.Error())
		return ""
	}
	return fmt.Sprintf("%s", plaintext)
}
