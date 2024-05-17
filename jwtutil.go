package krakend

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"
	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/kubernetes"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
)

var pluginName = "krakend-jwt-validation"

type pluginConfig struct {
	VaultUrl       string
	VaultToken     string
	VaultRoleName  string
	VaultTokenPath string
}

var (
	jwtSecret          string
	redisHost          string
	redisPort          string
	redisPassword      string
	redisSecureEnable  bool
	rdb                *redis.Client
	isRetrieveMetadata = false
	syncMu             sync.Mutex
	rwMutex            sync.RWMutex
	defaultKid         string
	jwtCache           = make(map[string]int64)
	vaultClient        *vault.Client
)

var jwtconfig = pluginConfig{}

func Middleware(log logging.Logger, c config.ServiceConfig) gin.HandlerFunc {
	extraConfig := c.ExtraConfig[pluginName].(map[string]interface{})
	jwtconfig.VaultUrl = extraConfig["vaultUrl"].(string)
	jwtconfig.VaultToken = extraConfig["vaultToken"].(string)
	jwtconfig.VaultRoleName = extraConfig["vaultRoleName"].(string)
	jwtconfig.VaultTokenPath = extraConfig["vaultTokenPath"].(string)
	return gin.HandlerFunc(func(c *gin.Context) {
		req := c.Request
		w := c.Writer
		log.Debug("Validate JWT Token: ", req.URL.Path)

		if req.URL.Path == "/__health" || req.URL.Path == "/favicon.ico" {
			c.Next()
			return
		}

		token := req.Header.Get("Authorization")
		if len(strings.TrimSpace(token)) == 0 {
			atCookie, err := req.Cookie("at")
			if err != nil {
				exp := JwtVerificationException{
					MessageCode: TOKEN_NOT_FOUND,
					MessageKey:  ErrMap[TOKEN_NOT_FOUND],
					Cause:       "Token not found from cookie / authorization header.",
				}
				log.Error(exp)
				w.WriteHeader(401)
				json.NewEncoder(w).Encode(exp)
				return
			}
			token = atCookie.Value
		}

		token = strings.ReplaceAll(token, "Bearer ", "")

		_, err := jwtconfig.Parse(token)

		if err != nil {
			log.Error(err)
			w.Header().Set("Content-Type", "application/json")

			exception := err.(JwtVerificationException)

			w.WriteHeader(401)
			if exception.MessageCode == "Internal Error" {
				w.WriteHeader(500)
			}

			json.NewEncoder(w).Encode(exception)
		} else {
			c.Next()
		}
	})
}

func (c pluginConfig) Parse(token string) (jwtToken *jwt.Token, err error) {
	defer func() {
		if r := recover(); r != nil {
			jwtToken = nil

			switch t := r.(type) {
			case JwtVerificationException:
				err = t

				rwMutex.Lock()
				delete(jwtCache, token)
				rwMutex.Unlock()
			default:
				msg := fmt.Sprintf("%v", r)
				err = JwtVerificationException{MessageCode: "Internal Error", MessageKey: msg, Cause: msg}
			}
		}
	}()

	c.populateVaultClient()

	checkIfTokenRevoke(token)

	rwMutex.RLock()
	jwtExpDurationInCache := jwtCache[token]
	rwMutex.RUnlock()

	if jwtExpDurationInCache != 0 {
		if time.Now().Unix() > jwtExpDurationInCache {
			err = JwtVerificationException{
				MessageCode: TOKEN_EXPIRED,
				MessageKey:  ErrMap[TOKEN_EXPIRED],
				Cause:       "Token from cache detected expired",
			}
		}
	} else {
		kid := c.RetrieveKidFromToken(token)
		jwtToken, err = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			if defaultKid == kid {
				return []byte(jwtSecret), nil
			} else {
				certificate := retrieveCertificateMetadata(kid, vaultClient)
				return jwt.ParseRSAPublicKeyFromPEM([]byte(certificate))
			}
		})

		if err != nil {
			if err.Error() == "Token is expired" {
				err = JwtVerificationException{
					MessageCode: TOKEN_EXPIRED,
					MessageKey:  ErrMap[TOKEN_EXPIRED],
					Cause:       err.Error(),
				}
			} else {
				err = JwtVerificationException{
					MessageCode: SIGNATURE_NOT_MATCH,
					MessageKey:  ErrMap[SIGNATURE_NOT_MATCH],
					Cause:       err.Error(),
				}
			}
		} else {
			claims := jwtToken.Claims.(jwt.MapClaims)

			rwMutex.Lock()
			jwtCache[token] = int64(claims["exp"].(float64))
			rwMutex.Unlock()
		}
	}

	return jwtToken, err
}

func (c pluginConfig) populateVaultClient() {
	syncMu.Lock()
	defer syncMu.Unlock()
	if !isRetrieveMetadata {
		vaultClient = c.constructVaultClient()
		retrieveSystemMetadata(vaultClient)
		isRetrieveMetadata = true
	}
}

func retrieveJtiFromToken(token string) string {
	jwtToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		panic("Failed to retrieve jti from token.")
	}
	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
		return claims["jti"].(string)
	} else {
		panic("Jti not found from token.")
	}
}

func (c pluginConfig) RetrieveKidFromToken(token string) string {
	jwtToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		panic("Failed to retrieve kid from token.")
	}
	if kid, ok := jwtToken.Header["kid"].(string); ok {
		return kid
	} else {
		panic("Kid not found from token.")
	}
}

func checkIfTokenRevoke(token string) {
	populateRdb()

	// Ping the Redis server to verify the connection
	jti := retrieveJtiFromToken(token)
	exists, err := rdb.Exists(context.Background(), jti).Result()

	if err == nil && exists != 1 {
		exists, err = rdb.Exists(context.Background(), token).Result()
	}

	if err != nil {
		panic(fmt.Sprintf("Error occured when check if token exist on redis: %v", err))
	} else if exists != 1 {
		exception := JwtVerificationException{
			MessageCode: SESSION_TIMEOUT,
			MessageKey:  ErrMap[SESSION_TIMEOUT],
			Cause:       "Token not found inside redis storage.",
		}
		panic(exception)
	}
}

func populateRdb() {
	syncMu.Lock()
	defer syncMu.Unlock()
	if rdb == nil {
		redisOption := &redis.Options{
			Addr:     redisHost + ":" + redisPort,
			Password: redisPassword,
			DB:       0,
		}

		if redisSecureEnable {
			redisOption.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}

		rdb = redis.NewClient(redisOption)

		pong, err := rdb.Ping(context.Background()).Result()

		if err != nil {
			panic(fmt.Sprintf("Failed to connect to Redis: %v", err))
		}
		fmt.Println("Connected to Redis:", pong)
	}
}

func (c pluginConfig) constructVaultClient() *vault.Client {
	fmt.Println("Retrieve metadata from vault")
	// Create a new Vault client
	client, err := vault.NewClient(vault.DefaultConfig())
	if err != nil {
		panic(fmt.Sprintf("Failed to create Vault client: %v", err))
	}

	err = client.SetAddress(c.VaultUrl)
	if err != nil {
		panic(fmt.Sprintf("Failed to set vault address: %v", err))
	}

	if len(strings.TrimSpace(c.VaultToken)) != 0 {
		client.SetToken(c.VaultToken)
	} else if len(strings.TrimSpace(c.VaultRoleName)) != 0 {
		tokenFilePath := "/var/run/secrets/kubernetes.io/serviceaccount/token"

		if len(strings.TrimSpace(c.VaultTokenPath)) != 0 {
			tokenFilePath = c.VaultTokenPath
		}

		k8sAuth, err := auth.NewKubernetesAuth(c.VaultRoleName, auth.WithServiceAccountTokenPath(tokenFilePath))

		if err != nil {
			panic(fmt.Sprintf("unable to initialize Kubernetes auth method: %v", err))
		}

		authInfo, err := client.Auth().Login(context.Background(), k8sAuth)

		if err != nil {
			panic(fmt.Sprintf("unable to log in with Kubernetes auth: %v", err))
		}
		if authInfo == nil {
			panic("No auth info was returned after login")
		}
	} else {
		panic("Vault Auth Metada Not Provided.")
	}

	return client
}

func retrieveSystemMetadata(client *vault.Client) {
	secret, err := client.Logical().Read("unicorn_sys/data/app")
	if err != nil {
		panic(fmt.Sprintf("Failed to retrieve secret: %v", err))
	}

	if secret == nil {
		panic("Secret not found")
	}

	// Extract the value from the secret
	value, ok := secret.Data["data"]
	if !ok {
		panic("Key not found in secret")
	}

	defaultKid, _ = value.(map[string]interface{})["app.token.kid"].(string)
	jwtSecret, _ = value.(map[string]interface{})["app.token.jwt-secret"].(string)
	redisHost, _ = value.(map[string]interface{})["spring.data.redis.host"].(string)
	redisPort, _ = value.(map[string]interface{})["spring.data.redis.port"].(string)
	redisSecureEnable, _ = value.(map[string]interface{})["spring.data.redis.ssl.enabled"].(bool)
	redisPassword, _ = value.(map[string]interface{})["spring.data.redis.password"].(string)
}

func retrieveCertificateMetadata(kid string, client *vault.Client) string {
	certMap, err := client.Logical().Read("pki/cert/" + kid)

	if err != nil {
		panic(fmt.Sprintf("Failed to retrieve certificate: %v", err))
	}

	if certMap == nil {
		panic("Certificate not found by kid: " + kid)
	}

	return certMap.Data["certificate"].(string)
}
