// Package google implements logging in through Google's OpenID Connect provider.
package google

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/time/rate"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"

	"github.com/dexidp/dex/connector"
	pkg_groups "github.com/dexidp/dex/pkg/groups"
)

const (
	issuerURL                           = "https://accounts.google.com"
	wildcardDomainToAdminEmail          = "*"
	defaultConcurrentGroupLookups       = 5
	defaultGroupLookupRequestsPerSecond = 10
	maxGroupLookupAttempts              = 4
)

// Config holds configuration options for Google logins.
type Config struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectURI"`

	Scopes []string `json:"scopes"` // defaults to "profile" and "email"

	// Optional list of whitelisted domains
	// If this field is nonempty, only users from a listed domain will be allowed to log in
	HostedDomains []string `json:"hostedDomains"`

	// Optional list of whitelisted groups
	// If this field is nonempty, only users from a listed group will be allowed to log in
	Groups []string `json:"groups"`

	// Optional path to service account json
	// If nonempty, and groups claim is made, will use authentication from file to
	// check groups with the admin directory api
	ServiceAccountFilePath string `json:"serviceAccountFilePath"`

	// Deprecated: Use DomainToAdminEmail
	AdminEmail string

	// Required if ServiceAccountFilePath
	// The map workspace domain to email of a GSuite super user which the service account will impersonate
	// when listing groups
	DomainToAdminEmail map[string]string

	// If this field is true, fetch direct group membership and transitive group membership
	FetchTransitiveGroupMembership bool `json:"fetchTransitiveGroupMembership"`

	// MaxConcurrentGroupLookups limits Directory API requests across all logins
	// using this connector. Values <= 0 use the default of 5.
	MaxConcurrentGroupLookups int `json:"maxConcurrentGroupLookups"`

	// MaxGroupLookupRequestsPerSecond limits request starts across this connector,
	// including retries. Values <= 0 use the default of 10; the burst is 1.
	MaxGroupLookupRequestsPerSecond float64 `json:"maxGroupLookupRequestsPerSecond"`

	// Optional value for the prompt parameter, defaults to consent when offline_access
	// scope is requested
	PromptType *string `json:"promptType"`
}

// Open returns a connector which can be used to login users through Google.
func (c *Config) Open(id string, logger *slog.Logger) (conn connector.Connector, err error) {
	logger = logger.With(slog.Group("connector", "type", "google", "id", id))
	if c.AdminEmail != "" {
		logger.Warn(`use "domainToAdminEmail.*" option instead of "adminEmail"`, "deprecated", true)
		if c.DomainToAdminEmail == nil {
			c.DomainToAdminEmail = make(map[string]string)
		}

		c.DomainToAdminEmail[wildcardDomainToAdminEmail] = c.AdminEmail
	}
	ctx, cancel := context.WithCancel(context.Background())

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	scopes := []string{oidc.ScopeOpenID}
	if len(c.Scopes) > 0 {
		scopes = append(scopes, c.Scopes...)
	} else {
		scopes = append(scopes, "profile", "email")
	}

	adminSrv := make(map[string]*admin.Service)

	// We know impersonation is required when using a service account credential
	// TODO: or is it?
	if len(c.DomainToAdminEmail) == 0 && c.ServiceAccountFilePath != "" {
		cancel()
		return nil, fmt.Errorf("directory service requires the domainToAdminEmail option to be configured")
	}

	if (len(c.DomainToAdminEmail) > 0) || slices.Contains(scopes, "groups") {
		for domain, adminEmail := range c.DomainToAdminEmail {
			srv, err := createDirectoryService(c.ServiceAccountFilePath, adminEmail, logger)
			if err != nil {
				cancel()
				return nil, fmt.Errorf("could not create directory service: %v", err)
			}

			adminSrv[domain] = srv
		}
	}

	promptType := "consent"
	if c.PromptType != nil {
		promptType = *c.PromptType
	}

	maxConcurrent := c.MaxConcurrentGroupLookups
	if maxConcurrent <= 0 {
		maxConcurrent = defaultConcurrentGroupLookups
	}
	maxRate := c.MaxGroupLookupRequestsPerSecond
	if maxRate <= 0 {
		maxRate = defaultGroupLookupRequestsPerSecond
	}
	clientID := c.ClientID
	return &googleConnector{
		redirectURI: c.RedirectURI,
		oauth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: c.ClientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
			RedirectURL:  c.RedirectURI,
		},
		verifier: provider.Verifier(
			&oidc.Config{ClientID: clientID},
		),
		logger:                         logger,
		cancel:                         cancel,
		hostedDomains:                  c.HostedDomains,
		groups:                         c.Groups,
		serviceAccountFilePath:         c.ServiceAccountFilePath,
		domainToAdminEmail:             c.DomainToAdminEmail,
		fetchTransitiveGroupMembership: c.FetchTransitiveGroupMembership,
		groupLookupSlots:               make(chan struct{}, maxConcurrent),
		groupLookupLimiter:             rate.NewLimiter(rate.Limit(maxRate), 1),
		adminSrv:                       adminSrv,
		promptType:                     promptType,
	}, nil
}

var (
	_ connector.CallbackConnector = (*googleConnector)(nil)
	_ connector.RefreshConnector  = (*googleConnector)(nil)
)

type googleConnector struct {
	redirectURI                    string
	oauth2Config                   *oauth2.Config
	verifier                       *oidc.IDTokenVerifier
	cancel                         context.CancelFunc
	logger                         *slog.Logger
	hostedDomains                  []string
	groups                         []string
	serviceAccountFilePath         string
	domainToAdminEmail             map[string]string
	fetchTransitiveGroupMembership bool
	groupLookupSlots               chan struct{}
	groupLookupLimiter             *rate.Limiter
	adminSrv                       map[string]*admin.Service
	promptType                     string
}

func (c *googleConnector) Close() error {
	c.cancel()
	return nil
}

func (c *googleConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, []byte, error) {
	if c.redirectURI != callbackURL {
		return "", nil, fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}

	var opts []oauth2.AuthCodeOption
	if len(c.hostedDomains) > 0 {
		preferredDomain := c.hostedDomains[0]
		if len(c.hostedDomains) > 1 {
			preferredDomain = "*"
		}
		opts = append(opts, oauth2.SetAuthURLParam("hd", preferredDomain))
	}

	if s.OfflineAccess {
		opts = append(opts, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", c.promptType))
	}

	return c.oauth2Config.AuthCodeURL(state, opts...), nil, nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

func (c *googleConnector) HandleCallback(s connector.Scopes, connData []byte, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}
	token, err := c.oauth2Config.Exchange(r.Context(), q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("google: failed to get token: %v", err)
	}

	return c.createIdentity(r.Context(), identity, s, token)
}

func (c *googleConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	t := &oauth2.Token{
		RefreshToken: string(identity.ConnectorData),
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.oauth2Config.TokenSource(ctx, t).Token()
	if err != nil {
		return identity, fmt.Errorf("google: failed to get token: %v", err)
	}

	return c.createIdentity(ctx, identity, s, token)
}

func (c *googleConnector) createIdentity(ctx context.Context, identity connector.Identity, s connector.Scopes, token *oauth2.Token) (connector.Identity, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return identity, errors.New("google: no id_token in token response")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return identity, fmt.Errorf("google: failed to verify ID Token: %v", err)
	}

	var claims struct {
		Username      string `json:"name"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		HostedDomain  string `json:"hd"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return identity, fmt.Errorf("oidc: failed to decode claims: %v", err)
	}

	// Google sometimes do not return username and other claims. It is correct, according to OIDC spec.
	// One option to solve this is to call the user endpoint, but Google throttles it more aggressive than
	// the token endpoint. For concurrent refreshes it is an unwanted behavior.
	// As a tradeoff, dex preserves previous username and preferred username if absent in the ide token
	// as a way to keep the claims and do not call the userinfo endpoint.
	if claims.Username == "" {
		claims.Username = identity.Username
	}

	if len(c.hostedDomains) > 0 {
		found := false
		for _, domain := range c.hostedDomains {
			if claims.HostedDomain == domain {
				found = true
				break
			}
		}

		if !found {
			return identity, fmt.Errorf("oidc: unexpected hd claim %v", claims.HostedDomain)
		}
	}

	var groups []string
	if s.Groups && len(c.adminSrv) > 0 {
		groups, err = c.getGroups(ctx, claims.Email, c.fetchTransitiveGroupMembership)
		if err != nil {
			return identity, fmt.Errorf("google: could not retrieve groups: %v", err)
		}

		if len(c.groups) > 0 {
			groups = pkg_groups.Filter(groups, c.groups)
			if len(groups) == 0 {
				return identity, fmt.Errorf("google: user %q is not in any of the required groups", claims.Username)
			}
		}
	}

	identity = connector.Identity{
		UserID:        idToken.Subject,
		Username:      claims.Username,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		ConnectorData: []byte(token.RefreshToken),
		Groups:        groups,
	}
	return identity, nil
}

type groupLookupResult struct {
	groups []string
	err    error
}

// getGroups lists direct or transitive memberships, with bounded workers.
func (c *googleConnector) getGroups(ctx context.Context, email string, transitive bool) ([]string, error) {
	ctx, cancel := context.WithCancel(ctx)
	jobs := make(chan string)
	results := make(chan groupLookupResult)
	var workers sync.WaitGroup
	for i := 0; i < cap(c.groupLookupSlots); i++ {
		workers.Go(func() { c.groupLookupWorker(ctx, jobs, results) })
	}
	defer func() {
		cancel()
		workers.Wait()
	}()
	return collectGroupResults(ctx, email, transitive, jobs, results)
}

func (c *googleConnector) groupLookupWorker(ctx context.Context, jobs <-chan string, results chan<- groupLookupResult) {
	for {
		select {
		case <-ctx.Done():
			return
		case member := <-jobs:
			groups, err := c.listGroupEmails(ctx, member)
			select {
			case results <- groupLookupResult{groups, err}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func collectGroupResults(ctx context.Context, email string, transitive bool, jobs chan<- string, results <-chan groupLookupResult) ([]string, error) {
	// Only the coordinator touches the queue and visited set. Workers never
	// schedule children or wait for another worker while holding an API slot.
	pending := []string{email}
	seen := make(map[string]struct{})
	var groups []string
	inFlight := 0
	for len(pending) > 0 || inFlight > 0 {
		var ready chan<- string
		var member string
		if len(pending) > 0 {
			ready, member = jobs, pending[0]
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case ready <- member:
			pending = pending[1:]
			inFlight++
		case r := <-results:
			inFlight--
			if r.err != nil {
				return nil, r.err
			}
			for _, group := range r.groups {
				if _, exists := seen[group]; exists {
					continue
				}
				seen[group] = struct{}{}
				groups = append(groups, group)
				if transitive {
					pending = append(pending, group)
				}
			}
		}
	}
	sort.Strings(groups)
	return groups, nil
}

func (c *googleConnector) listGroupEmails(ctx context.Context, member string) ([]string, error) {
	var groupEmails []string
	pageToken := ""
	for {
		groupsList, err := c.fetchGroupPage(ctx, member, pageToken)
		if err != nil {
			return nil, fmt.Errorf("could not list groups: %w", err)
		}
		for _, group := range groupsList.Groups {
			// TODO (joelspeed): Make desired group key configurable
			groupEmails = append(groupEmails, group.Email)
		}
		if groupsList.NextPageToken == "" {
			break
		}
		pageToken = groupsList.NextPageToken
	}
	return groupEmails, nil
}

// fetchGroupPage releases the API slot before backing off, so other logins
// can continue. Every attempt is rate-limited and bound to the login context.
func (c *googleConnector) fetchGroupPage(ctx context.Context, member, pageToken string) (*admin.Groups, error) {
	srv, err := c.findAdminService(c.extractDomainFromEmail(member))
	if err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case c.groupLookupSlots <- struct{}{}:
		}
		if err := c.groupLookupLimiter.Wait(ctx); err != nil {
			<-c.groupLookupSlots
			return nil, err
		}
		page, err := srv.Groups.List().UserKey(member).PageToken(pageToken).Context(ctx).Do()
		<-c.groupLookupSlots
		if !isGroupQuotaError(err) || attempt+1 == maxGroupLookupAttempts {
			return page, err
		}
		delay := time.Second<<attempt + time.Duration(rand.IntN(250))*time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func isGroupQuotaError(err error) bool {
	var apiErr *googleapi.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.Code == http.StatusTooManyRequests {
		return true
	}
	if apiErr.Code == http.StatusForbidden {
		for _, item := range apiErr.Errors {
			if item.Reason == "rateLimitExceeded" || item.Reason == "userRateLimitExceeded" {
				return true
			}
		}
	}
	return false
}

func (c *googleConnector) findAdminService(domain string) (*admin.Service, error) {
	adminSrv, ok := c.adminSrv[domain]
	if !ok {
		adminSrv, ok = c.adminSrv[wildcardDomainToAdminEmail]
		c.logger.Debug("using wildcard admin email to fetch groups", "admin_email", c.domainToAdminEmail[wildcardDomainToAdminEmail])
	}

	if !ok {
		return nil, fmt.Errorf("unable to find super admin email, domainToAdminEmail for domain: %s not set, %s is also empty", domain, wildcardDomainToAdminEmail)
	}

	return adminSrv, nil
}

// extracts the domain name from an email input. If the email is valid, it returns the domain name after the "@" symbol.
// However, in the case of a broken or invalid email, it returns a wildcard symbol.
func (c *googleConnector) extractDomainFromEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at >= 0 {
		_, domain := email[:at], email[at+1:]

		return domain
	}

	return wildcardDomainToAdminEmail
}

// getCredentialsFromFilePath reads and returns the service account credentials from the file at the provided path.
// If an error occurs during the read, it is returned.
func getCredentialsFromFilePath(serviceAccountFilePath string) ([]byte, error) {
	jsonCredentials, err := os.ReadFile(serviceAccountFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading credentials from file: %v", err)
	}
	return jsonCredentials, nil
}

// getCredentialsFromDefault retrieves the application's default credentials.
// If the default credential is empty, it attempts to create a new service with metadata credentials.
// If successful, it returns the service and nil error.
// If unsuccessful, it returns the error and a nil service.
func getCredentialsFromDefault(ctx context.Context, email string, logger *slog.Logger) ([]byte, *admin.Service, error) {
	credential, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch application default credentials: %w", err)
	}

	if credential.JSON == nil {
		logger.Info("JSON is empty, using flow for GCE")
		service, err := createServiceWithMetadataServer(ctx, email, logger)
		if err != nil {
			return nil, nil, err
		}
		return nil, service, nil
	}

	return credential.JSON, nil, nil
}

// createServiceWithMetadataServer creates a new service using metadata server.
// If an error occurs during the process, it is returned along with a nil service.
func createServiceWithMetadataServer(ctx context.Context, adminEmail string, logger *slog.Logger) (*admin.Service, error) {
	serviceAccountEmail, err := metadata.EmailWithContext(ctx, "default")
	logger.Info("discovered serviceAccountEmail", "email", serviceAccountEmail)

	if err != nil {
		return nil, fmt.Errorf("unable to get service account email from metadata server: %v", err)
	}

	config := impersonate.CredentialsConfig{
		TargetPrincipal: serviceAccountEmail,
		Scopes:          []string{admin.AdminDirectoryGroupReadonlyScope},
		Lifetime:        0,
		Subject:         adminEmail,
	}

	tokenSource, err := impersonate.CredentialsTokenSource(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to impersonate with %s, error: %v", adminEmail, err)
	}

	return admin.NewService(ctx, option.WithHTTPClient(oauth2.NewClient(ctx, tokenSource)))
}

// createDirectoryService sets up super user impersonation and creates an admin client for calling
// the google admin api. If no serviceAccountFilePath is defined, the application default credential
// is used.
func createDirectoryService(serviceAccountFilePath, email string, logger *slog.Logger) (service *admin.Service, err error) {
	var jsonCredentials []byte

	ctx := context.Background()
	if serviceAccountFilePath == "" {
		logger.Warn("the application default credential is used since the service account file path is not used")
		jsonCredentials, service, err = getCredentialsFromDefault(ctx, email, logger)
		if err != nil {
			return
		}
		if service != nil {
			return
		}
	} else {
		jsonCredentials, err = getCredentialsFromFilePath(serviceAccountFilePath)
		if err != nil {
			return
		}
	}
	config, err := google.JWTConfigFromJSON(jsonCredentials, admin.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		return nil, fmt.Errorf("unable to parse client secret file to config: %v", err)
	}

	// Only attempt impersonation when there is a user configured
	if email != "" {
		config.Subject = email
	}

	return admin.NewService(ctx, option.WithHTTPClient(config.Client(ctx)))
}
