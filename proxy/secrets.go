package main

// Secrets provider — loads API keys / tokens from an external secrets backend
// and injects them into the process environment via os.Setenv so that the rest
// of the proxy can use os.Getenv as normal without any other code changes.
//
// Controlled by SECRETS_PROVIDER (default: "env"):
//
//	vault  — HashiCorp Vault KV v2 (token or AppRole auth)
//	aws    — AWS Secrets Manager (static creds or EC2 IMDSv2)
//	gcp    — GCP Secret Manager  (service-account JSON or GCE metadata)
//	azure  — Azure Key Vault     (service principal or managed identity)
//
// In all cases secrets are expected to be a flat JSON object:
//
//	{ "ADMIN_TOKEN": "...", "OPENAI_API_KEY": "...", ... }

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

var secretsProviderName = "env"

func initSecretsProvider() error {
	p := strings.ToLower(os.Getenv("SECRETS_PROVIDER"))
	switch p {
	case "vault":
		secretsProviderName = "vault"
		return loadFromVault()
	case "aws":
		secretsProviderName = "aws"
		return loadFromAWS()
	case "gcp":
		secretsProviderName = "gcp"
		return loadFromGCP()
	case "azure":
		secretsProviderName = "azure"
		return loadFromAzure()
	default:
		return nil
	}
}

func injectSecrets(secrets map[string]string, provider string) {
	for k, v := range secrets {
		if v != "" {
			os.Setenv(k, v)
		}
	}
	log.Printf("🔐 Loaded %d secrets from %s", len(secrets), provider)
}

// ─── HashiCorp Vault ─────────────────────────────────────────────────────────
//
// Required:  VAULT_ADDR        e.g. https://vault.example.com:8200
//            VAULT_SECRET_PATH  e.g. secret/data/agentarmor  (KV v2)
// Auth:      VAULT_TOKEN  OR  VAULT_ROLE_ID + VAULT_SECRET_ID (AppRole)
// Optional:  VAULT_SKIP_VERIFY=true  (self-signed cert)

func loadFromVault() error {
	addr := strings.TrimRight(os.Getenv("VAULT_ADDR"), "/")
	path := os.Getenv("VAULT_SECRET_PATH")
	if addr == "" || path == "" {
		return fmt.Errorf("vault: VAULT_ADDR and VAULT_SECRET_PATH are required")
	}

	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		var err error
		token, err = vaultAppRoleLogin(addr)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequest(http.MethodGet, addr+"/v1/"+path, nil)
	if err != nil {
		return fmt.Errorf("vault: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := vaultClient().Do(req)
	if err != nil {
		return fmt.Errorf("vault: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault: HTTP %d: %s", resp.StatusCode, body)
	}

	// KV v2 envelope: { "data": { "data": { "KEY": "value", ... } } }
	var envelope struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("vault: decode response: %w", err)
	}

	injectSecrets(envelope.Data.Data, "Vault ("+path+")")
	return nil
}

func vaultAppRoleLogin(addr string) (string, error) {
	roleID := os.Getenv("VAULT_ROLE_ID")
	secretID := os.Getenv("VAULT_SECRET_ID")
	if roleID == "" || secretID == "" {
		return "", fmt.Errorf("vault: set VAULT_TOKEN or (VAULT_ROLE_ID + VAULT_SECRET_ID)")
	}

	body := fmt.Sprintf(`{"role_id":%q,"secret_id":%q}`, roleID, secretID)
	resp, err := vaultClient().Post(addr+"/v1/auth/approle/login", "application/json",
		strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("vault: AppRole login: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("vault: AppRole decode: %w", err)
	}
	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault: AppRole login returned empty token — check VAULT_ROLE_ID/VAULT_SECRET_ID")
	}
	return result.Auth.ClientToken, nil
}

func vaultClient() *http.Client {
	c := &http.Client{Timeout: 10 * time.Second}
	if os.Getenv("VAULT_SKIP_VERIFY") == "true" {
		c.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	return c
}

// ─── AWS Secrets Manager ─────────────────────────────────────────────────────
//
// Required:  AWS_REGION, AWS_SECRET_NAME  e.g. "agentarmor/prod"
// Creds:     AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY [+ AWS_SESSION_TOKEN]
//            OR EC2 instance profile (IMDSv2 — automatic if no static creds)

func loadFromAWS() error {
	region := os.Getenv("AWS_REGION")
	secretName := os.Getenv("AWS_SECRET_NAME")
	if region == "" || secretName == "" {
		return fmt.Errorf("aws: AWS_REGION and AWS_SECRET_NAME are required")
	}

	ak := os.Getenv("AWS_ACCESS_KEY_ID")
	sk := os.Getenv("AWS_SECRET_ACCESS_KEY")
	st := os.Getenv("AWS_SESSION_TOKEN")

	if ak == "" || sk == "" {
		var err error
		ak, sk, st, err = awsIMDSv2Creds()
		if err != nil {
			return fmt.Errorf("aws: no credentials (set AWS_ACCESS_KEY_ID+AWS_SECRET_ACCESS_KEY or use an instance profile): %w", err)
		}
	}

	endpoint := "https://secretsmanager." + region + ".amazonaws.com/"
	payload := []byte(`{"SecretId":` + jsonQuote(secretName) + `}`)

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("aws: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	awsSigV4Sign(req, payload, region, "secretsmanager", ak, sk, st)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("aws: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("aws: HTTP %d: %s", resp.StatusCode, body)
	}

	var result struct {
		SecretString string `json:"SecretString"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("aws: decode response: %w", err)
	}

	var secrets map[string]string
	if err := json.Unmarshal([]byte(result.SecretString), &secrets); err != nil {
		return fmt.Errorf("aws: parse secrets JSON: %w", err)
	}

	injectSecrets(secrets, "AWS Secrets Manager ("+secretName+")")
	return nil
}

// awsIMDSv2Creds retrieves temporary credentials from the EC2 Instance Metadata Service v2.
func awsIMDSv2Creds() (ak, sk, st string, err error) {
	client := &http.Client{Timeout: 3 * time.Second}
	base := "http://169.254.169.254"

	// Step 1: get IMDSv2 session token
	req, _ := http.NewRequest(http.MethodPut, base+"/latest/api/token", nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("IMDS unreachable: %w", err)
	}
	defer resp.Body.Close()
	imdsToken, _ := io.ReadAll(resp.Body)

	// Step 2: discover the IAM role name
	req2, _ := http.NewRequest(http.MethodGet,
		base+"/latest/meta-data/iam/security-credentials/", nil)
	req2.Header.Set("X-aws-ec2-metadata-token", string(imdsToken))
	resp2, err := client.Do(req2)
	if err != nil {
		return "", "", "", fmt.Errorf("IMDS role lookup: %w", err)
	}
	defer resp2.Body.Close()
	roleBytes, _ := io.ReadAll(resp2.Body)
	role := strings.TrimSpace(string(roleBytes))
	if role == "" {
		return "", "", "", fmt.Errorf("no IAM role attached to this instance")
	}

	// Step 3: fetch credentials for the role
	req3, _ := http.NewRequest(http.MethodGet,
		base+"/latest/meta-data/iam/security-credentials/"+role, nil)
	req3.Header.Set("X-aws-ec2-metadata-token", string(imdsToken))
	resp3, err := client.Do(req3)
	if err != nil {
		return "", "", "", fmt.Errorf("IMDS creds: %w", err)
	}
	defer resp3.Body.Close()

	var creds struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
	}
	if err := json.NewDecoder(resp3.Body).Decode(&creds); err != nil {
		return "", "", "", fmt.Errorf("IMDS creds decode: %w", err)
	}
	return creds.AccessKeyID, creds.SecretAccessKey, creds.Token, nil
}

// awsSigV4Sign adds AWS SigV4 Authorization and date headers to the request.
func awsSigV4Sign(req *http.Request, body []byte, region, service, ak, sk, sessionToken string) {
	now := time.Now().UTC()
	dateLong := now.Format("20060102T150405Z")
	dateShort := now.Format("20060102")

	req.Header.Set("X-Amz-Date", dateLong)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}

	// Canonical headers (sorted)
	host := req.URL.Host
	req.Header.Set("Host", host)

	signedHeaders := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if sessionToken != "" {
		signedHeaders = append(signedHeaders, "x-amz-security-token")
	}
	sort.Strings(signedHeaders)

	var canonHeaders strings.Builder
	for _, h := range signedHeaders {
		canonHeaders.WriteString(h + ":" + strings.TrimSpace(req.Header.Get(h)) + "\n")
	}

	bodyHash := fmt.Sprintf("%x", sha256.Sum256(body))
	canonRequest := strings.Join([]string{
		req.Method,
		req.URL.Path,
		req.URL.RawQuery,
		canonHeaders.String(),
		strings.Join(signedHeaders, ";"),
		bodyHash,
	}, "\n")

	credScope := strings.Join([]string{dateShort, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		dateLong,
		credScope,
		fmt.Sprintf("%x", sha256.Sum256([]byte(canonRequest))),
	}, "\n")

	signingKey := awsHMAC(awsHMAC(awsHMAC(awsHMAC(
		[]byte("AWS4"+sk), dateShort), region), service), "aws4_request")
	signature := fmt.Sprintf("%x", awsHMAC(signingKey, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		ak, credScope, strings.Join(signedHeaders, ";"), signature,
	))
}

func awsHMAC(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// ─── GCP Secret Manager ───────────────────────────────────────────────────────
//
// Required:  GCP_PROJECT_ID, GCP_SECRET_NAME  e.g. "agentarmor-secrets"
// Optional:  GCP_SECRET_VERSION  (default: "latest")
// Auth:      GOOGLE_APPLICATION_CREDENTIALS=path/to/key.json (service account)
//            OR automatic GCE/GKE/Cloud Run metadata server

func loadFromGCP() error {
	project := os.Getenv("GCP_PROJECT_ID")
	secret := os.Getenv("GCP_SECRET_NAME")
	version := os.Getenv("GCP_SECRET_VERSION")
	if project == "" || secret == "" {
		return fmt.Errorf("gcp: GCP_PROJECT_ID and GCP_SECRET_NAME are required")
	}
	if version == "" {
		version = "latest"
	}

	token, err := gcpAccessToken()
	if err != nil {
		return fmt.Errorf("gcp: get access token: %w", err)
	}

	apiURL := fmt.Sprintf(
		"https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s/versions/%s:access",
		project, secret, version,
	)
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return fmt.Errorf("gcp: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("gcp: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gcp: HTTP %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Payload struct {
			Data string `json:"data"` // base64-encoded
		} `json:"payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("gcp: decode response: %w", err)
	}

	raw, err := base64.StdEncoding.DecodeString(result.Payload.Data)
	if err != nil {
		return fmt.Errorf("gcp: base64 decode: %w", err)
	}

	var secrets map[string]string
	if err := json.Unmarshal(raw, &secrets); err != nil {
		return fmt.Errorf("gcp: parse secrets JSON: %w", err)
	}

	injectSecrets(secrets, "GCP Secret Manager ("+secret+"/"+version+")")
	return nil
}

func gcpAccessToken() (string, error) {
	if keyFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); keyFile != "" {
		return gcpTokenFromKeyFile(keyFile)
	}
	return gcpTokenFromMetadata()
}

func gcpTokenFromMetadata() (string, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest(http.MethodGet,
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GCE metadata server unreachable — set GOOGLE_APPLICATION_CREDENTIALS for service account auth: %w", err)
	}
	defer resp.Body.Close()
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("metadata token decode: %w", err)
	}
	return result.AccessToken, nil
}

func gcpTokenFromKeyFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read key file: %w", err)
	}

	var sa struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(data, &sa); err != nil {
		return "", fmt.Errorf("parse service account JSON: %w", err)
	}
	if sa.Type != "service_account" {
		return "", fmt.Errorf("key file type is %q, expected service_account", sa.Type)
	}
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}

	// Parse RSA private key (PKCS#8 or PKCS#1)
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("invalid PEM in private_key")
	}
	var rsaKey *rsa.PrivateKey
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		rsaKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("private key is not RSA")
		}
	} else if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		rsaKey = key
	} else {
		return "", fmt.Errorf("cannot parse private key")
	}

	// Build and sign JWT
	now := time.Now().Unix()
	headerJSON, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claimsJSON, _ := json.Marshal(map[string]interface{}{
		"iss":   sa.ClientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   sa.TokenURI,
		"iat":   now,
		"exp":   now + 3600,
	})
	msgB64 := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	h := sha256.New()
	h.Write([]byte(msgB64))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("JWT sign: %w", err)
	}
	jwt := msgB64 + "." + base64.RawURLEncoding.EncodeToString(sig)

	// Exchange JWT for access token
	resp, err := http.PostForm(sa.TokenURI, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	})
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("token decode: %w", err)
	}
	return tok.AccessToken, nil
}

// ─── Azure Key Vault ──────────────────────────────────────────────────────────
//
// Required:  AZURE_KEYVAULT_URL  e.g. https://myvault.vault.azure.net
//            AZURE_SECRET_NAME   e.g. agentarmor-secrets  (stores JSON)
// Auth:      AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET (service principal)
//            OR automatic managed identity (Azure VMs / AKS — no extra vars needed)

func loadFromAzure() error {
	vaultURL := strings.TrimRight(os.Getenv("AZURE_KEYVAULT_URL"), "/")
	secretName := os.Getenv("AZURE_SECRET_NAME")
	if vaultURL == "" || secretName == "" {
		return fmt.Errorf("azure: AZURE_KEYVAULT_URL and AZURE_SECRET_NAME are required")
	}

	token, err := azureAccessToken("https://vault.azure.net")
	if err != nil {
		return fmt.Errorf("azure: get access token: %w", err)
	}

	apiURL := vaultURL + "/secrets/" + secretName + "?api-version=7.4"
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return fmt.Errorf("azure: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("azure: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("azure: HTTP %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("azure: decode response: %w", err)
	}

	var secrets map[string]string
	if err := json.Unmarshal([]byte(result.Value), &secrets); err != nil {
		return fmt.Errorf("azure: parse secrets JSON from Key Vault value: %w", err)
	}

	injectSecrets(secrets, "Azure Key Vault ("+secretName+")")
	return nil
}

func azureAccessToken(resource string) (string, error) {
	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")

	if tenantID != "" && clientID != "" && clientSecret != "" {
		return azureClientCredentials(tenantID, clientID, clientSecret, resource)
	}
	return azureManagedIdentityToken(resource)
}

func azureClientCredentials(tenantID, clientID, clientSecret, resource string) (string, error) {
	tokenURL := "https://login.microsoftonline.com/" + tenantID + "/oauth2/v2.0/token"
	resp, err := http.PostForm(tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {resource + "/.default"},
	})
	if err != nil {
		return "", fmt.Errorf("client credentials request: %w", err)
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("token decode: %w", err)
	}
	if tok.Error != "" {
		return "", fmt.Errorf("%s: %s", tok.Error, tok.ErrorDesc)
	}
	return tok.AccessToken, nil
}

func azureManagedIdentityToken(resource string) (string, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	apiURL := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" +
		url.QueryEscape(resource)
	req, _ := http.NewRequest(http.MethodGet, apiURL, nil)
	req.Header.Set("Metadata", "true")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("managed identity endpoint unreachable — set AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET for service principal auth: %w", err)
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("managed identity token decode: %w", err)
	}
	return tok.AccessToken, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
