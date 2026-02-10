# authlete-java


Use `sbt inspect tree` 

"/api/v1/auth/logout"
"/api/v1/auth/login"

```ts
package config;

/**
 * This schema defines the Authentication Configuration.
 */
export interface AuthenticationConfiguration {
    /**
     * Authentication Authority
     */
    authority: string;
    /**
     * Callback URL
     */
    callbackUrl: string;
    /**
     * Client ID
     */
    clientId: string;
    /**
     * Client Type
     */
    clientType?: ClientType;
    /**
     * Enable Self Sign Up
     */
    enableSelfSignup?: boolean;
    /**
     * Jwt Principal Claim
     */
    jwtPrincipalClaims: string[];
    /**
     * Jwt Principal Claim Mapping
     */
    jwtPrincipalClaimsMapping?: string[];
    /**
     * LDAP Configuration in case the Provider is LDAP
     */
    ldapConfiguration?: LDAPConfiguration;
    /**
     * Oidc Configuration for Confidential Client Type
     */
    oidcConfiguration?: OidcClientConfig;
    provider:           AuthProvider;
    /**
     * Custom OIDC Authentication Provider Name
     */
    providerName: string;
    /**
     * List of Public Key URLs
     */
    publicKeyUrls: string[];
    /**
     * This is used by auth provider provide response as either id_token or code.
     */
    responseType?: ResponseType;
    /**
     * Saml Configuration that is applicable only when the provider is Saml
     */
    samlConfiguration?: SamlSSOClientConfig;
    /**
     * Token Validation Algorithm to use.
     */
    tokenValidationAlgorithm?: TokenValidationAlgorithm;
}

/**
 * Client Type
 */
export enum ClientType {
    Confidential = "confidential",
    Public = "public",
}

/**
 * LDAP Configuration in case the Provider is LDAP
 *
 * LDAP Configuration
 */
export interface LDAPConfiguration {
    /**
     * All attribute name
     */
    allAttributeName?: string;
    /**
     * Roles should be reassign every time user login
     */
    authReassignRoles?: string[];
    /**
     * Json string of roles mapping between LDAP roles and Ranger roles
     */
    authRolesMapping?: string;
    /**
     * Password for LDAP Admin
     */
    dnAdminPassword: string;
    /**
     * Distinguished Admin name with search capabilities
     */
    dnAdminPrincipal: string;
    /**
     * Group Name attribute name
     */
    groupAttributeName?: string;
    /**
     * Group attribute value
     */
    groupAttributeValue?: string;
    /**
     * Group base distinguished name
     */
    groupBaseDN?: string;
    /**
     * Group Member Name attribute name
     */
    groupMemberAttributeName?: string;
    /**
     * LDAP server address without scheme(Example :- localhost)
     */
    host: string;
    /**
     * If enable need to give full dn to login
     */
    isFullDn?: boolean;
    /**
     * Email attribute name
     */
    mailAttributeName: string;
    /**
     * No of connection to create the pool with
     */
    maxPoolSize?: number;
    /**
     * Port of the server
     */
    port: number;
    /**
     * Admin role name
     */
    roleAdminName?: string;
    /**
     * LDAPS (secure LDAP) or LDAP
     */
    sslEnabled?: boolean;
    /**
     * Truststore Configuration
     */
    trustStoreConfig?: TruststoreConfig;
    /**
     * Truststore Type e.g. TrustAll, HostName, JVMDefault, CustomTrustStore.
     */
    truststoreConfigType?: TruststoreConfigType;
    /**
     * Truststore format e.g. PKCS12, JKS.
     */
    truststoreFormat?: string;
    /**
     * User base distinguished name
     */
    userBaseDN: string;
    /**
     * User Name attribute name
     */
    usernameAttributeName?: string;
}

/**
 * Truststore Configuration
 */
export interface TruststoreConfig {
    /**
     * CustomTrust Configuration
     */
    customTrustManagerConfig?: CustomTrustManagerConfig;
    /**
     * HostName Configuration
     */
    hostNameConfig?: HostNameConfig;
    /**
     * JVMDefault Configuration
     */
    jvmDefaultConfig?: JVMDefaultConfig;
    /**
     * TrustAll Configuration
     */
    trustAllConfig?: TrustAllConfig;
}

/**
 * CustomTrust Configuration
 */
export interface CustomTrustManagerConfig {
    /**
     * Examine validity dates of certificate
     */
    examineValidityDates?: boolean;
    /**
     * Truststore file format
     */
    trustStoreFileFormat?: string;
    /**
     * Truststore file password
     */
    trustStoreFilePassword?: string;
    /**
     * Truststore file path
     */
    trustStoreFilePath?: string;
    /**
     * list of host names to verify
     */
    verifyHostname?: boolean;
}

/**
 * HostName Configuration
 */
export interface HostNameConfig {
    /**
     * list of acceptable host names
     */
    acceptableHostNames?: string[];
    /**
     * Allow wildcards
     */
    allowWildCards?: boolean;
}

/**
 * JVMDefault Configuration
 */
export interface JVMDefaultConfig {
    /**
     * list of host names to verify
     */
    verifyHostname?: boolean;
}

/**
 * TrustAll Configuration
 */
export interface TrustAllConfig {
    /**
     * Examine validity dates of certificate
     */
    examineValidityDates?: boolean;
}

/**
 * Truststore Type e.g. TrustAll, HostName, JVMDefault, CustomTrustStore.
 */
export enum TruststoreConfigType {
    CustomTrustStore = "CustomTrustStore",
    HostName = "HostName",
    JVMDefault = "JVMDefault",
    TrustAll = "TrustAll",
}

/**
 * Oidc Configuration for Confidential Client Type
 *
 * Oidc client security configs.
 */
export interface OidcClientConfig {
    /**
     * Callback Url.
     */
    callbackUrl?: string;
    /**
     * Client Authentication Method.
     */
    clientAuthenticationMethod?: ClientAuthenticationMethod;
    /**
     * Custom Params.
     */
    customParams?: { [key: string]: any };
    /**
     * Disable PKCE.
     */
    disablePkce?: boolean;
    /**
     * Discovery Uri for the Client.
     */
    discoveryUri?: string;
    /**
     * Client ID.
     */
    id?: string;
    /**
     * Validity for the JWT Token created from SAML Response
     */
    maxAge?: string;
    /**
     * Max Clock Skew
     */
    maxClockSkew?: string;
    /**
     * Preferred Jws Algorithm.
     */
    preferredJwsAlgorithm?: string;
    /**
     * Prompt whether login/consent
     */
    prompt?: string;
    /**
     * Auth0 Client Secret Key.
     */
    responseType?: string;
    /**
     * Oidc Request Scopes.
     */
    scope?: string;
    /**
     * Client Secret.
     */
    secret?: string;
    /**
     * Server Url.
     */
    serverUrl?: string;
    /**
     * Tenant in case of Azure.
     */
    tenant?: string;
    /**
     * Validity for the JWT Token created from SAML Response
     */
    tokenValidity?: number;
    /**
     * IDP type (Example Google,Azure).
     */
    type?: string;
    /**
     * Use Nonce.
     */
    useNonce?: string;
}

/**
 * Client Authentication Method.
 */
export enum ClientAuthenticationMethod {
    ClientSecretBasic = "client_secret_basic",
    ClientSecretJwt = "client_secret_jwt",
    ClientSecretPost = "client_secret_post",
    PrivateKeyJwt = "private_key_jwt",
}

/**
 * OpenMetadata Server Authentication Provider. Make sure configure same auth providers as
 * the one configured on OpenMetadata server.
 */
export enum AuthProvider {
    Auth0 = "auth0",
    AwsCognito = "aws-cognito",
    Azure = "azure",
    Basic = "basic",
    CustomOidc = "custom-oidc",
    Google = "google",
    LDAP = "ldap",
    Okta = "okta",
    Openmetadata = "openmetadata",
    Saml = "saml",
}

/**
 * This is used by auth provider provide response as either id_token or code.
 *
 * Response Type
 */
export enum ResponseType {
    Code = "code",
    IDToken = "id_token",
}

/**
 * Saml Configuration that is applicable only when the provider is Saml
 *
 * SAML SSO client security configs.
 */
export interface SamlSSOClientConfig {
    /**
     * Get logs from the Library in debug mode
     */
    debugMode?: boolean;
    idp:        Idp;
    security?:  Security;
    sp:         SP;
}

/**
 * This schema defines defines the identity provider config.
 */
export interface Idp {
    /**
     * Authority URL to redirect the users on Sign In page
     */
    authorityUrl?: string;
    /**
     * Identity Provider Entity ID usually same as the SSO login URL.
     */
    entityId: string;
    /**
     * X509 Certificate
     */
    idpX509Certificate?: string;
    /**
     * Authority URL to redirect the users on Sign In page
     */
    nameId?: string;
    /**
     * SSO Login URL.
     */
    ssoLoginUrl: string;
}

/**
 * This schema defines defines the security config for SAML.
 */
export interface Security {
    /**
     * KeyStore Alias
     */
    keyStoreAlias?: string;
    /**
     * KeyStore File Path
     */
    keyStoreFilePath?: string;
    /**
     * KeyStore Password
     */
    keyStorePassword?: string;
    /**
     * Encrypt Name Id while sending requests from SP.
     */
    sendEncryptedNameId?: boolean;
    /**
     * Sign the Authn Request while sending.
     */
    sendSignedAuthRequest?: boolean;
    /**
     * Want the Metadata of this SP to be signed.
     */
    signSpMetadata?: boolean;
    /**
     * Only accept valid signed and encrypted assertions if the relevant flags are set
     */
    strictMode?: boolean;
    /**
     * Validity for the JWT Token created from SAML Response
     */
    tokenValidity?: number;
    /**
     * In case of strict mode whether to validate XML format.
     */
    validateXml?: boolean;
    /**
     * SP requires the assertion received to be encrypted.
     */
    wantAssertionEncrypted?: boolean;
    /**
     * SP requires the assertions received to be signed.
     */
    wantAssertionsSigned?: boolean;
    /**
     * SP requires the messages received to be signed.
     */
    wantMessagesSigned?: boolean;
}

/**
 * This schema defines defines the identity provider config.
 */
export interface SP {
    /**
     * Assertion Consumer URL.
     */
    acs: string;
    /**
     * Service Provider Entity ID usually same as the SSO login URL.
     */
    callback: string;
    /**
     * Service Provider Entity ID.
     */
    entityId: string;
    /**
     * Sp Private Key for Signing and Encryption Only
     */
    spPrivateKey?: string;
    /**
     * X509 Certificate
     */
    spX509Certificate?: string;
}

/**
 * Token Validation Algorithm to use.
 */
export enum TokenValidationAlgorithm {
    Rs256 = "RS256",
    Rs384 = "RS384",
    Rs512 = "RS512",
}
```

```java
  public boolean checkAuthentication(Http.Request request, Set<Users.Role> roles) {
    String token = fetchToken(request, true);
    Users user;
    if (token != null) {
      user = authWithToken(token, true);
    } else {
      token = fetchToken(request, false);
      user = authWithToken(token, false);
    }
    if (user != null) {
      boolean foundRole = false;
      boolean useNewAuthz = runtimeConfigCache.getBoolean(GlobalConfKeys.useNewRbacAuthz.getKey());
      if (!useNewAuthz) {
        if (roles.contains(user.getRole())) {
          // So we can audit any super admin actions.
          // If there is a use case also lookup customer and put it in context
          UserWithFeatures userWithFeatures = new UserWithFeatures().setUser(user);
          RequestContext.put(USER, userWithFeatures);
          foundRole = true;
        }
      } else {
        for (Users.Role usersRole : roles) {
          Role role = Role.get(user.getCustomerUUID(), usersRole.name());
          if (RoleBinding.checkUserHasRole(user.getUuid(), role.getRoleUUID())) {
            UserWithFeatures userWithFeatures = new UserWithFeatures().setUser(user);
            RequestContext.put(USER, userWithFeatures);
            foundRole = true;
          }
        }
      }
      return foundRole;
    }
    return false;
  }

  public boolean superAdminAuthentication(Http.Request request) {
    return checkAuthentication(
        request, new HashSet<>(Collections.singletonList(Users.Role.SuperAdmin)));
  }

  // Calls that require admin authentication should allow
  // both admins and super-admins.
  public boolean adminAuthentication(Http.Request request) {
    return checkAuthentication(
        request, new HashSet<>(Arrays.asList(Users.Role.Admin, Users.Role.SuperAdmin)));
  }

  public void adminOrThrow(Http.Request request) {
    if (!adminAuthentication(request)) {
      throw new PlatformServiceException(FORBIDDEN, "Only Admins can perform this operation.");
    }
  }

  // TODO: Consider changing to a method annotation
  public void superAdminOrThrow(Http.Request request) {
    if (!superAdminAuthentication(request)) {
      throw new PlatformServiceException(
          FORBIDDEN, "Only Super Admins can perform this operation.");
    }
  }
```
`By default, the PlayWebContext holds the data (cookies, session, ...) necessary for the response`. A call is needed to the `supplementResponse` method to add that data to the Result.This only happens when the pac4j framework returns a `Result`


```http
curl -v http://play-pac4j-java-demo.herokuapp.com/oidc/index.html
*   Trying 3.208.158.124...
* TCP_NODELAY set
* Connected to play-pac4j-java-demo.herokuapp.com (3.208.158.124) port 80 (#0)
> GET /oidc/index.html HTTP/1.1
> Host: play-pac4j-java-demo.herokuapp.com
> User-Agent: curl/7.64.1
> Accept: */*
> 
< HTTP/1.1 302 Found
< Server: Cowboy
< Connection: keep-alive
< Pragma: no-cache
< Expires: 0
< Location: https://accounts.google.com/o/oauth2/v2/auth?scope=openid+profile+email&response_type=code&redirect_uri=https%3A%2F%2Fplay-pac4j-java-demo.herokuapp.com%2Fcallback%3Fclient_name%3DOidcClient&state=186c2b58d2&code_challenge_method=S256&prompt=consent&client_id=343992089165-i1es0qvej18asl33mvlbeq750i3ko32k.apps.googleusercontent.com&code_challenge=EdTX1IDfCU-RYqWZR2tNpuc218CWMSRJ892fzSl_3lk
< Set-Cookie: PLAY_SESSION=eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7InBhYzRqU2Vzc2lvbklkIjoiZGQxYjIyNzItMDc4NC00MGU4LWFkY2YtZjZmNWU2YmJjYjQyIn0sIm5iZiI6MTYxNDk3NDMwOCwiaWF0IjoxNjE0OTc0MzA4fQ.172v8brSm88NnpiTrFOnBQ6Sygg0ay2w-L8Z21ZcH0A; Path=/; HTTPOnly
< Set-Cookie: pac4jCsrfToken=d12a5db76f6d46bea926a681e2b793bd; Path=/; Domain=play-pac4j-java-demo.herokuapp.com
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< X-Frame-Options: DENY
< X-Xss-Protection: 1; mode=block
< X-Content-Type-Options: nosniff
< Date: Fri, 05 Mar 2021 19:58:28 GMT
< Content-Length: 0
< Via: 1.1 vegur
< 
* Connection #0 to host play-pac4j-java-demo.herokuapp.com left intact
* Closing connection 0
```


```java
  private static String fetchToken(Http.Request request, boolean isApiToken) {
    String header, cookie;
    if (isApiToken) {
      header = API_TOKEN_HEADER;
      cookie = COOKIE_API_TOKEN;
    } else {
      header = AUTH_TOKEN_HEADER;
      cookie = COOKIE_AUTH_TOKEN;
    }
    Optional<String> headerValueOp = request.header(header);
    Optional<Http.Cookie> cookieValue = request.getCookie(cookie);

    if (headerValueOp.isPresent()) {
      return headerValueOp.get();
    }
    // If we are accessing authenticated pages, the auth token would be in the cookie
    return cookieValue.map(Cookie::value).orElse(null);// cookieValue.map(cookie -> cookie.value())
  }


public Users getCurrentAuthenticatedUser(Http.Request request) {
    String token;
    Users user = null;
    boolean useOAuth = confGetter.getGlobalConf(GlobalConfKeys.useOauth);
    Optional<Http.Cookie> cookieValue = request.getCookie(COOKIE_PLAY_SESSION);
    if (useOAuth) {
      final PlayWebContext context = new PlayWebContext(request);
      final ProfileManager profileManager = new ProfileManager(context, sessionStore);
      if (profileManager.isAuthenticated()) {
        CommonProfile profile = profileManager.getProfile(CommonProfile.class).get();
        String emailAttr = confGetter.getGlobalConf(GlobalConfKeys.oidcEmailAttribute);
        String email;
        if (emailAttr.equals("")) {
          email = profile.getEmail();
        } else {
          email = (String) profile.getAttribute(emailAttr);
        }
        if (email != null) {
          user = Users.getByEmail(email.toLowerCase());
        }
      }
      if (user == null) {
        // Defaulting to regular flow to support dual login.
        token = fetchToken(request, false /* isApiToken */);
        user = authWithToken(token, false);
        if (user != null && !user.getRole().equals(Users.Role.SuperAdmin)) {
          user = null; // We want to only allow SuperAdmins access.
        }
      }
    } else {
      token = fetchToken(request, false /* isApiToken */);
      user = authWithToken(token, false);
    }
    if (user == null && !cookieValue.isPresent()) {
      token = fetchToken(request, true /* isApiToken */);
      if (token == null) {
        UUID userUuid = jwtVerifier.verify(request, API_JWT_HEADER);
        if (userUuid != null) {
          user = Users.getOrBadRequest(userUuid);
        }
      } else {
        user = authWithToken(token, true);
      }
    }
    return user;
  }

  public static final String COOKIE_AUTH_TOKEN = "authToken";
  public static final String AUTH_TOKEN_HEADER = "X-AUTH-TOKEN";
  public static final String COOKIE_API_TOKEN = "apiToken";
  public static final String API_TOKEN_HEADER = "X-AUTH-YW-API-TOKEN";
  public static final String API_JWT_HEADER = "X-AUTH-YW-API-JWT";
  public static final String COOKIE_PLAY_SESSION = "PLAY_SESSION";
```

if `isApiToken` then we use `header = API_TOKEN_HEADER;`(X-AUTH-YW-API-TOKEN) and `cookie = COOKIE_API_TOKEN;`(apiToken)

if not we use `header = AUTH_TOKEN_HEADER;`(X-AUTH-TOKEN) and `cookie = COOKIE_AUTH_TOKEN;`(authToken)

` token = fetchToken(request, false /* isApiToken */);` will check `X-AUTH-TOKEN` header or `authToken` cookie with preference to header value

`token = fetchToken(request, true /* isApiToken */);` will check `X-AUTH-YW-API-TOKEN` header or `apiToken` cookie

For SSO, `isApiToken` is not supported and only super admins can login with `X-AUTH-TOKEN` header or `authToken` cookie



```java
  public static final String AUTH_TOKEN = "authToken";
  public static final String API_TOKEN = "apiToken";

 @ApiModel(description = "Session information")
  @RequiredArgsConstructor
  public static class SessionInfo {

    @ApiModelProperty(value = "Auth token")
    public final String authToken;

    @ApiModelProperty(value = "API token")
    public final String apiToken;

    @ApiModelProperty(value = "API token version")
    public final Long apiTokenVersion;

    @ApiModelProperty(value = "Customer UUID")
    public final UUID customerUUID;

    @ApiModelProperty(value = "User UUID")
    public final UUID userUUID;
  }

SessionInfo(authToken,apiToken,apiTokenVersion,customerUUID,userUUID)
  @With(TokenAuthenticator.class)
  @AuthzPath
  public Result getSessionInfo(Http.Request request) {
    Users user = CommonUtils.getUserFromContext();
    Customer cust = Customer.get(user.getCustomerUUID());
    Optional<Cookie> authCookie = request.cookie(AUTH_TOKEN);
    SessionInfo sessionInfo =
        new SessionInfo(
            authCookie.isPresent() ? authCookie.get().value() : null,
            null,
            null,
            cust.getUuid(),
            user.getUuid());
    return withData(sessionInfo);
  } 

 @ApiOperation(value = "UI_ONLY", hidden = true)
  public Result login(Http.Request request) {
    Users user =
        loginHandler.login(
            formFactory.getFormDataOrBadRequest(request, CustomerLoginFormData.class).get());

    Customer cust = Customer.get(user.getCustomerUUID());

    String authToken = user.createAuthToken();
    SessionInfo sessionInfo =
        new SessionInfo(authToken, null, null, cust.getUuid(), user.getUuid());
    RequestContext.update(IS_AUDITED, val -> val.set(true));
    Audit.create(
        user,
        request.path(),
        request.method(),
        Audit.TargetType.User,
        user.getUuid().toString(),
        Audit.ActionType.Login,
        null,
        null,
        null,
        request.remoteAddress());
    return withData(sessionInfo)
        .withCookies(
            Http.Cookie.builder(AUTH_TOKEN, authToken)
                .withSecure(request.secure())
                .withHttpOnly(false)
                .build(),
            Http.Cookie.builder("customerId", cust.getUuid().toString())
                .withSecure(request.secure())
                .withHttpOnly(false)
                .build(),
            Http.Cookie.builder("userId", user.getUuid().toString())
                .withSecure(request.secure())
                .withHttpOnly(false)
                .build());
  }

@Transactional
  private Result registerCustomer(
      CustomerRegisterFormData data,
      boolean isSuper,
      boolean generateApiToken,
      Http.Request request) {
    Customer cust = Customer.create(data.getCode(), data.getName());
    Users.Role role = Users.Role.Admin;
    if (isSuper) {
      role = Users.Role.SuperAdmin;
    }
    passwordPolicyService.checkPasswordPolicy(cust.getUuid(), data.getPassword());

    alertDestinationService.createDefaultDestination(cust.getUuid());
    alertConfigurationService.createDefaultConfigs(cust);

    Users user = Users.createPrimary(data.getEmail(), data.getPassword(), role, cust.getUuid());

    boolean useNewAuthz =
        runtimeConfigFactory.globalRuntimeConf().getBoolean("yb.rbac.use_new_authz");

    // Sync all the built-in roles when a new customer is created.
    R__Sync_System_Roles.syncSystemRoles(cust.getUuid());

    if (useNewAuthz) {
      Role newRbacRole = Role.get(cust.getUuid(), role.name());

      // Now add the role binding for the above user.
      ResourceGroup resourceGroup =
          ResourceGroup.getSystemDefaultResourceGroup(cust.getUuid(), user);
      // Create a single role binding for the user.
      RoleBinding createdRoleBinding =
          roleBindingUtil.createRoleBinding(
              user.getUuid(), newRbacRole.getRoleUUID(), RoleBindingType.System, resourceGroup);

      log.info(
          "Created new system role binding for user '{}' (email '{}') of new customer '{}', "
              + "with role '{}' (name '{}'), and default role binding '{}'.",
          user.getUuid(),
          user.getEmail(),
          cust.getUuid(),
          newRbacRole.getRoleUUID(),
          newRbacRole.getName(),
          createdRoleBinding.toString());
    }

    String authToken = user.createAuthToken();
    String apiToken = generateApiToken ? user.upsertApiToken() : null;
    SessionInfo sessionInfo =
        new SessionInfo(
            authToken, apiToken, user.getApiTokenVersion(), user.getCustomerUUID(), user.getUuid());
    // When there is no authenticated user in context; we just pretend that the user
    // created himself for auditing purpose.
    RequestContext.putIfAbsent(
        TokenAuthenticator.USER, userService.getUserWithFeatures(cust, user));
    auditService()
        .createAuditEntryWithReqBody(
            request,
            Audit.TargetType.Customer,
            cust.getUuid().toString(),
            Audit.ActionType.Register);
    return withData(sessionInfo)
        .withCookies(
            Http.Cookie.builder(AUTH_TOKEN, sessionInfo.authToken)
                .withSecure(request.secure())
                .withHttpOnly(false)
                .build());
  }


  @ApiOperation(value = "UI_ONLY", hidden = true)
  @With(TokenAuthenticator.class)
  @AuthzPath
  public Result logout() {
    Users user = CommonUtils.getUserFromContext();
    if (user != null) {
      refreshAccessToken.stop(user);
      user.deleteAuthToken();
    }
    return YBPSuccess.empty().discardingCookie(AUTH_TOKEN);
  }
```  

```java
  @ApiOperation(value = "UI_ONLY", hidden = true)
  public Result insecure_login(Http.Request request) {
    List<Customer> allCustomers = Customer.getAll();
    if (allCustomers.size() != 1) {
      throw new PlatformServiceException(
          FORBIDDEN, "Cannot allow insecure with multiple customers.");
    }
    String securityLevel =
        (String) configHelper.getConfig(ConfigHelper.ConfigType.Security).get("level");
    if (securityLevel != null && securityLevel.equals("insecure")) {
      List<Users> users = Users.getAllReadOnly();
      if (users.isEmpty()) {
        throw new PlatformServiceException(FORBIDDEN, "No read only customer exists.");
      }
      Users user = users.get(0);
      if (user == null) {
        throw new PlatformServiceException(FORBIDDEN, "Invalid User saved.");
      }
      String apiToken = user.upsertApiToken();

      SessionInfo sessionInfo =
          new SessionInfo(
              null, apiToken, user.getApiTokenVersion(), user.getCustomerUUID(), user.getUuid());
      RequestContext.update(IS_AUDITED, val -> val.set(true));
      Audit.create(
          user,
          request.path(),
          request.method(),
          Audit.TargetType.User,
          user.getUuid().toString(),
          Audit.ActionType.Login,
          null,
          null,
          null,
          request.remoteAddress());
      return withData(sessionInfo)
          .withCookies(
              Http.Cookie.builder(API_TOKEN, apiToken)
                  .withSecure(request.secure())
                  .withHttpOnly(false)
                  .build());
    }
    throw new PlatformServiceException(FORBIDDEN, "Insecure login unavailable.");
  }
  @With(TokenAuthenticator.class)
  @ApiOperation(value = "Regenerate and fetch API token", response = SessionInfo.class)
  @AuthzPath
  public Result api_token(UUID customerUUID, Long apiTokenVersion, Http.Request request) {
    Users user = CommonUtils.getUserFromContext();

    if (user == null) {
      throw new PlatformServiceException(
          BAD_REQUEST, "Could not find User from given credentials.");
    }

    String apiToken = user.upsertApiToken(apiTokenVersion);
    SessionInfo sessionInfo =
        new SessionInfo(null, apiToken, user.getApiTokenVersion(), customerUUID, user.getUuid());
    auditService()
        .createAuditEntryWithReqBody(
            request,
            Audit.TargetType.Customer,
            customerUUID.toString(),
            Audit.ActionType.GenerateApiToken);
    return withData(sessionInfo)
        .withCookies(
            Http.Cookie.builder(API_TOKEN, apiToken)
                .withSecure(request.secure())
                .withMaxAge(FOREVER)
                .withHttpOnly(false)
                .build());
  }
```  

```java
   play.filters.csrf.CSRFFilter
    play.filters.headers.SecurityHeadersFilter
    play.filters.hosts.AllowedHostsFilter

```    
The CSRF filter (specifically the AddCSRFTokenAction and related logic) will set a CSRF token in the session if it is not already present, especially on GET requests for HTML. This operation causes Play to create/set a `PLAY_SESSION ` cookie,

```java
  @Override
  public CompletionStage<Result> call(Http.Request req) {

    CSRFActionHelper helper =
        new CSRFActionHelper(sessionConfiguration, config, tokenSigner, tokenProvider);

    play.api.mvc.Request<RequestBody> taggedRequest = helper.tagRequestFromHeader(req.asScala());

    if (helper.getTokenToValidate(taggedRequest).isEmpty()) {
      // No token in header and we have to create one if not found, so create a new token
      CSRF.Token newToken = helper.generateToken();

      // Create a new Scala RequestHeader with the token
      taggedRequest = helper.tagRequest(taggedRequest, newToken);

      // Also add it to the response
      return delegate
          .call(new RequestImpl(taggedRequest))
          .thenApply(result -> placeToken(req, result, newToken));
    }
    return delegate.call(new RequestImpl(taggedRequest));
  }

  /** Places the CSRF token in the session or in a cookie (if a cookie name is configured) */
  private Result placeToken(Http.Request req, final Result result, CSRF.Token token) {
    if (config.cookieName().isDefined()) {
      scala.Option<String> domain = sessionConfiguration.domain();
      Http.Cookie cookie =
          new Http.Cookie(
              config.cookieName().get(),
              token.value(),
              null,
              sessionConfiguration.path(),
              domain.isDefined() ? domain.get() : null,
              config.secureCookie(),
              config.httpOnlyCookie(),
              OptionConverters.toJava(config.sameSiteCookie())
                  .map(Cookie.SameSite::asJava)
                  .orElse(null),
              config.partitionedCookie());
      return result.withCookies(cookie);
    }
    return result.addingToSession(req, token.name(), token.value());
  }
```
In Play Framework, `request.attrs` (or request.attributes in some variants) is a mechanism for attaching and retrieving typed, per-request data. It is an immutable map that allows middleware, filters, or application code to attach arbitrary data to a request, keyed by a special type-safe key called a `TypedKey`.

- Type: It is an instance of `TypedMap`.
- Key: The keys are instances of `TypedKey[T]` (Scala) or `TypedKey<T>` (Java), which ensures type safety.
- Purpose: Used for passing metadata, context, or flags along a request’s lifecycle without polluting headers or parameters.

Suppose a filter wants to add user information to the request for controllers to access:

```scala
val UserKey = TypedKey[User]("user")
val requestWithUser = request.addAttr(UserKey, userInstance)
val user = requestWithUser.attrs.get(UserKey)
```

Common Use Cases

- Storing authenticated user info.
- Storing route metadata (such as handler definitions).
- Passing context from filters to actions.


```java
/** This action adds a CSRF token to the request and response if not already there. */
@With(AddCSRFTokenAction.class)
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface AddCSRFToken {}

```


```java
public class AddCSRFTokenAction extends Action<AddCSRFToken> {
}

import play.mvc.Http;
import play.libs.typedmap.TypedKey;

// Define a key
public static final TypedKey<String> USERNAME = TypedKey.create("username");

// Somewhere in middleware or a filter:
Http.Request newRequest = request.addAttr(USERNAME, "alice");

// Later, in a controller or action:
String username = newRequest.attrs().get(USERNAME);
```

  public static final String AUTH_TOKEN = "authToken";

```curl
curl -v http://localhost:9000/about.html
* Host localhost:9000 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:9000...
* Connected to localhost (::1) port 9000
> GET /about.html HTTP/1.1
> Host: localhost:9000
> User-Agent: curl/8.7.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< ETag: "8886d922923c61234b64d9ea49447be19d83bd13"
< Set-Cookie: PLAY_SESSION=eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImNzcmZUb2tlbiI6ImM0M2E1OGRjMzIxYzljOTM1NTI1MTU5M2MzMzQ2OTMxOTNlN2NhZWQtMTc1MTQ5NjEyOTY4OS1kOTk3OGM0YmIwYTY1YjdiMzYwMGEyNzYifSwibmJmIjoxNzUxNDk2MTI5LCJpYXQiOjE3NTE0OTYxMjl9.D1R3bY8DIn9brZLV1AvB3JsVNAn5i07IQG9z-V7WvWI; SameSite=Lax; Path=/; HTTPOnly
< Accept-Ranges: bytes
< Cache-Control: no-cache
< Last-Modified: Mon, 23 Jun 2025 10:28:32 GMT
< Referrer-Policy: origin-when-cross-origin, strict-origin-when-cross-origin
< X-Frame-Options: DENY
< X-XSS-Protection: 1; mode=block
< X-Content-Type-Options: nosniff
< X-Permitted-Cross-Domain-Policies: master-only
< Date: Wed, 02 Jul 2025 22:42:09 GMT
< Content-Type: text/html; charset=UTF-8
< Content-Length: 475
< 
<!doctype html>
<html lang="en" data-beasties-container>
<head>
  <meta charset="utf-8">
  <title>Ui</title>
  <base href="/">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/x-icon" href="favicon.ico">
<link rel="stylesheet" href="styles-5INURTSO.css"></head>
<body>
  <app-root></app-root>
<script src="polyfills-FFHMD2TL.js" type="module"></script><script src="main-UPO4YBNO.js" type="module"></script></body>
</html>
* Connection #0 to host localhost left intact
``` 

```java
  public Users getCurrentAuthenticatedUser(Http.Request request) {
    String token;
    Users user = null;
    boolean useOAuth = confGetter.getGlobalConf(GlobalConfKeys.useOauth);
    Optional<Http.Cookie> cookieValue = request.getCookie(COOKIE_PLAY_SESSION);
    if (useOAuth) {
      final PlayWebContext context = new PlayWebContext(request);
      final ProfileManager profileManager = new ProfileManager(context, sessionStore);
      if (profileManager.isAuthenticated()) {
        CommonProfile profile = profileManager.getProfile(CommonProfile.class).get();
        String emailAttr = confGetter.getGlobalConf(GlobalConfKeys.oidcEmailAttribute);
        String email;
        if (emailAttr.equals("")) {
          email = profile.getEmail();
        } else {
          email = (String) profile.getAttribute(emailAttr);
        }
        if (email != null) {
          user = Users.getByEmail(email.toLowerCase());
        }
      }
      if (user == null) {
        // Defaulting to regular flow to support dual login.
        token = fetchToken(request, false /* isApiToken */);
        user = authWithToken(token, false);
        if (user != null && !user.getRole().equals(Users.Role.SuperAdmin)) {
          user = null; // We want to only allow SuperAdmins access.
        }
      }
    } else {
      token = fetchToken(request, false /* isApiToken */);
      user = authWithToken(token, false);
    }
    if (user == null && !cookieValue.isPresent()) {
      token = fetchToken(request, true /* isApiToken */);
      if (token == null) {
        UUID userUuid = jwtVerifier.verify(request, API_JWT_HEADER);
        if (userUuid != null) {
          user = Users.getOrBadRequest(userUuid);
        }
      } else {
        user = authWithToken(token, true);
      }
    }
    return user;
  }
```  
When OAuth is enabled, it relies on the session established by the third-party provider, mapping the external identity (email) to a local user account, 




```java
@Slf4j
public class SecureAction extends Action<Result> {
}
```
In Play Framework:

`Action<T>` is a base class representing an action that processes a request and returns a result of type `T`.

When you extend `Action<Result>`, you're saying: “This action processes an HTTP request and returns a Play `Result` (like an HTTP 200 OK, 401 Unauthorized, etc.).”

```java
/**
 * <p>Default callback logic:</p>
 * <p>The credentials are extracted from the current request to fetch the user profile (from the identity provider) which is then saved in
 * the web session. Finally, the user is redirected back to the originally requested url (or to the <code>defaultUrl</code>).</p>
 *
 */
@Getter
@Setter
@ToString(callSuper = true)
@Slf4j
@Accessors(chain = true)
public class DefaultCallbackLogic extends AbstractExceptionAwareLogic implements CallbackLogic {

    /** Constant <code>INSTANCE</code> */
    public static final DefaultCallbackLogic INSTANCE = new DefaultCallbackLogic();

    private ClientFinder clientFinder = new DefaultCallbackClientFinder();

    private SavedRequestHandler savedRequestHandler = new DefaultSavedRequestHandler();

    /** {@inheritDoc} */
    @Override
    public Object perform(final Config config, final String inputDefaultUrl, final Boolean inputRenewSession,
                          final String defaultClient, final FrameworkParameters parameters) {

        LOGGER.debug("=== CALLBACK ===");

        // checks
        val ctx = buildContext(config, parameters);
        val webContext = ctx.webContext();
        val httpActionAdapter = config.getHttpActionAdapter();
        assertNotNull("httpActionAdapter", httpActionAdapter);

        HttpAction action;
        try {
            assertNotNull("clientFinder", clientFinder);

            // default values
            final String defaultUrl;
            defaultUrl = Objects.requireNonNullElse(inputDefaultUrl, Pac4jConstants.DEFAULT_URL_VALUE);
            val renewSession = inputRenewSession == null || inputRenewSession;

            assertNotBlank(Pac4jConstants.DEFAULT_URL, defaultUrl);
            val clients = config.getClients();
            assertNotNull("clients", clients);

            val foundClients = clientFinder.find(clients, webContext, defaultClient);
            assertTrue(foundClients != null && foundClients.size() == 1,
                "unable to find one indirect client for the callback: check the callback URL for a client name parameter or suffix path"
                    + " or ensure that your configuration defaults to one indirect client");
            val foundClient = foundClients.get(0);
            LOGGER.debug("foundClient: {}", foundClient);
            assertNotNull("foundClient", foundClient);

            var credentials = foundClient.getCredentials(ctx).orElse(null);
            LOGGER.debug("extracted credentials: {}", credentials);
            credentials = foundClient.validateCredentials(ctx, credentials).orElse(null);
            LOGGER.debug("validated credentials: {}", credentials);

            if (credentials != null && !credentials.isForAuthentication()) {

                action = foundClient.processLogout(ctx, credentials);

            } else {

                if (credentials != null) {
                    val optProfile = foundClient.getUserProfile(ctx, credentials);
                    LOGGER.debug("optProfile: {}", optProfile);
                    if (optProfile.isPresent()) {
                        val profile = optProfile.get();
                        val saveProfileInSession = ((BaseClient) foundClient).getSaveProfileInSession(webContext, profile);
                        val multiProfile = ((BaseClient) foundClient).isMultiProfile(webContext, profile);
                        LOGGER.debug("saveProfileInSession: {} / multiProfile: {}", saveProfileInSession, multiProfile);
                        saveUserProfile(ctx, config, profile, saveProfileInSession, multiProfile, renewSession);
                    }
                }

                action = redirectToOriginallyRequestedUrl(ctx, defaultUrl);
            }

        } catch (final RuntimeException e) {
            return handleException(e, httpActionAdapter, webContext);
        }

        return httpActionAdapter.adapt(action, webContext);
    }

    /**
     * <p>saveUserProfile.</p>
     *
     * @param ctx a {@link CallContext} object
     * @param config a {@link Config} object
     * @param profile a {@link UserProfile} object
     * @param saveProfileInSession a boolean
     * @param multiProfile a boolean
     * @param renewSession a boolean
     */
    protected void saveUserProfile(final CallContext ctx, final Config config, final UserProfile profile,
                                   final boolean saveProfileInSession, final boolean multiProfile, final boolean renewSession) {
        val manager = ctx.profileManagerFactory().apply(ctx.webContext(), ctx.sessionStore());
        if (profile != null) {
            manager.save(saveProfileInSession, profile, multiProfile);
            if (renewSession) {
                renewSession(ctx, config);
            }
        }
    }

    /**
     * <p>renewSession.</p>
     *
     * @param ctx a {@link CallContext} object
     * @param config a {@link Config} object
     */
    protected void renewSession(final CallContext ctx, final Config config) {
        val context = ctx.webContext();
        val sessionStore = ctx.sessionStore();

        val optOldSessionId = sessionStore.getSessionId(context, true);
        if (optOldSessionId.isEmpty()) {
            LOGGER.error("No old session identifier retrieved although the session creation has been requested");
        } else {
            val oldSessionId = optOldSessionId.get();
            val renewed = sessionStore.renewSession(context);
            if (renewed) {
                val optNewSessionId = sessionStore.getSessionId(context, true);
                if (optNewSessionId.isEmpty()) {
                    LOGGER.error("No new session identifier retrieved although the session creation has been requested");
                } else {
                    val newSessionId = optNewSessionId.get();
                    LOGGER.debug("Renewing session: {} -> {}", oldSessionId, newSessionId);
                    val clients = config.getClients();
                    if (clients != null) {
                        val clientList = clients.getClients();
                        for (val client : clientList) {
                            val baseClient = (BaseClient) client;
                            baseClient.notifySessionRenewal(ctx, oldSessionId);
                        }
                    }
                }
            } else {
                LOGGER.error("Unable to renew the session. The session store may not support this feature");
            }
        }
    }

    /**
     * <p>redirectToOriginallyRequestedUrl.</p>
     *
     * @param ctx a {@link CallContext} object
     * @param defaultUrl a {@link String} object
     * @return a {@link HttpAction} object
     */
    protected HttpAction redirectToOriginallyRequestedUrl(final CallContext ctx, final String defaultUrl) {
        return savedRequestHandler.restore(ctx, defaultUrl);
    }
}
```

1. Extract Credentials:
It pulls credentials (like authorization codes or tokens) from the callback request.
2. Fetch User Profile:
Using the credentials, it retrieves the authenticated user’s profile from the identity provider.
3. Save to Session:
If configured, the user profile is stored in the web session so the user stays logged in across requests.
4. Redirect User:
Once authenticated, the user is redirected to their originally requested URL or a default URL.


`perform(...)`:
The main entry point. It coordinates finding the right client, extracting and validating credentials, saving the user profile, and redirecting.

`saveUserProfile(...)`:
Manages saving the user profile in the session and renewing the session if needed.
`renewSession(...)`:
Handles renewing the web session (e.g., to prevent session fixation attacks after login).

`redirectToOriginallyRequestedUrl(...)`:
Restores and redirects the user to the URL they originally wanted to access before being redirected for authentication.

In `DefaultCallbackLogic.java`, when a user authenticates, their profile is saved using the `ProfileManager`.
The ProfileManager (see ProfileManager.java) stores the user profile(s) in the session using the key `Pac4jConstants.USER_PROFILES`. So, in the underlying session (for example, a Play session, JEE session, etc.), the user profiles are stored under the attribute name pac4jUserProfiles.

The session might contain:

- Authentication data (like pac4jUserProfiles)
- CSRF tokens
- User preferences
- Shopping cart data
- Flash messages (temporary notifications)

 the session content is signed to ensure integrity — i.e., to detect tampering.

 Play uses `play.http.secret.key = "your-very-long-secret-key"`


```java
 /**
   * Create a random auth token for the Users and store it in the DB.
   *
   * @return authToken
   */
  public String createAuthToken() {
    Date tokenExpiryDate = new DateTime().minusDays(1).toDate();
    if (authTokenIssueDate == null || authTokenIssueDate.before(tokenExpiryDate)) {
      SecureRandom randomGenerator = new SecureRandom();
      // Keeping the length as 128 bits.
      byte[] randomBytes = new byte[16];
      randomGenerator.nextBytes(randomBytes);
      // Converting to hexadecimal encoding
      authToken = new BigInteger(1, randomBytes).toString(16);
      authTokenIssueDate = new Date();
      save();
    }
    return authToken;
```



Session and flash cookies are stored in JSON Web Token (JWT) format. The encoding is transparent to Play, but there some useful properties of JWT which can be leveraged for session cookies, and can be configured through application.conf. Note that JWT is typically used in an HTTP header value, which is not what is active here – in addition, the JWT is signed using the secret, but is not encrypted by Play.


```sh
Set-Cookie: PLAY_SESSION=eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7InBhYzRqU2Vzc2lvbklkIjoiZGQxYjIyNzItMDc4NC00MGU4LWFkY2YtZjZmNWU2YmJjYjQyIn0sIm5iZiI6MTYxNDk3NDMwOCwiaWF0IjoxNjE0OTc0MzA4fQ.172v8brSm88NnpiTrFOnBQ6Sygg0ay2w-L8Z21ZcH0A
```


## URL Encoded Cookie Encoding

The session cookie uses the JWT cookie encoding. If you want, you can revert back to URL encoded cookie encoding by switching to play.api.mvc.LegacyCookiesModule in the application.conf file:

```conf
play.modules.disabled+="play.api.mvc.CookiesModule"
play.modules.enabled+="play.api.mvc.LegacyCookiesModule"
```


```conf
# Session configuration
session = {

  # The cookie name
  cookieName = "PLAY_SESSION"

  # Whether the secure attribute of the cookie should be set to true
  secure = false

  # The max age to set on the cookie.
  # If null, the cookie expires when the user closes their browser.
  # An important thing to note, this only sets when the browser will discard the cookie.
  maxAge = null

  # Whether the HTTP only attribute of the cookie should be set to true
  httpOnly = true

  # The value of the SameSite attribute of the cookie. Set to null for no SameSite attribute.
  # Possible values are "lax", "strict" and "none". If misconfigured it's set to null.
  sameSite = "lax"

  # The domain to set on the session cookie
  # If null, does not set a domain on the session cookie.
  domain = null

  # The session path
  # Must start with /.
  path = ${play.http.context}

  jwt {
    # The JWT signature algorithm to use on the session cookie
    # uses 'alg' https://tools.ietf.org/html/rfc7515#section-4.1.1
    signatureAlgorithm = "HS256"

    # The time after which the session is automatically invalidated.
    # Use 'exp' https://tools.ietf.org/html/rfc7519#section-4.1.4
    expiresAfter = ${play.http.session.maxAge}

    # The amount of clock skew to accept between servers when performing date checks
    # If you have NTP or roughtime synchronizing between servers, you can enhance
    # security by tightening this value.
    clockSkew = 5 minutes

    # The claim key under which all user data is stored in the JWT.
    dataClaim = "data"
  }
}
```

```json
{
  "data": {
    "pac4jSessionId": "dd1b2272-0784-40e8-adcf-f6f5e6bbcb42"
  },
  "nbf": 1614974308,
  "iat": 1614974308
}
```


```conf
├── app                      → Application sources
│   ├── assets               → Compiled Asset sources
│   │   ├── javascripts      → Typically Coffee Script sources
│   │   └── stylesheets      → Typically LESS CSS sources
│   ├── controllers          → Application controllers
│   ├── models               → Application business layer
│   └── views                → Templates
├── build.sbt                → Application build script
├── conf                     → Configurations files and other non-compiled resources (on classpath)
│   ├── application.conf     → Main configuration file
│   └── routes               → Routes definition
├── dist                     → Arbitrary files to be included in your projects distribution
├── lib                      → Unmanaged libraries dependencies
├── logs                     → Logs folder
│   └── application.log      → Default log file
├── project                  → sbt configuration files
│   ├── build.properties     → Marker for sbt project
│   └── plugins.sbt          → sbt plugins including the declaration for Play itself
├── public                   → Public assets
│   ├── images               → Image files
│   ├── javascripts          → Javascript files
│   └── stylesheets          → CSS files
├── target                   → Generated files
│   ├── resolution-cache     → Information about dependencies
│   ├── scala-2.11            
│   │   ├── api              → Generated API docs
│   │   ├── classes          → Compiled class files
│   │   ├── routes           → Sources generated from routes
│   │   └── twirl            → Sources generated from templates
│   ├── universal            → Application packaging
│   └── web                  → Compiled web assets
└── test                     → source folder for unit or functional tests
```

What is Single Sign-On (SSO)?

Single Sign-On (SSO) is a user authentication process that allows a user to access multiple applications with one set of login credentials.


```sh
In sbt 2.0, the server is global to the project directory, but it acts as a machine-wide resource for all clients (terminals and IDEs) that are looking at that specific project.
```

The Multi-Client Broadcast

In sbt 2.0, the server maintains a list of all connected clients (this includes the sbtn process in your terminal and the Metals BSP connection)

When you run sbt compile in your terminal, the server performs the work.

- As the compiler finds errors, the server sends BSP 
- Diagnostics notifications (build/publishDiagnostics) not just to the terminal that asked for the compile, but to all connected BSP clients.
- Metals, as a listening client, receives these notifications in real-time and updates the "Problems" view in VS Code immediately.

`Metals Is a Client (via BSP)`

On macOS / Linux (Unix Domain Sockets)

By default, sbt 2.0 prefers local sockets because they are faster and more secure than network ports.

```json
{
  "uri": "local:///Users/yourname/.sbt/1.0/server/6be87d.../sock"
}
```

Fallback (TCP Mode)
`{"uri":"tcp://127.0.0.1:4499"}`

The sbt runner 1.10.10 and later script defaults to using sbtn (GraalVM native-image client) for sbt 2.x. In sbt 2.0, sbt server sends the run task back to sbtn, which will fork a fresh JVM. All you have to do is:

`sbt run`

This avoids blocking the sbt server, and you can have multiple runs. 

`ls -l /opt/homebrew/var/postgresql@18` every file should say username admin

`rm -f /opt/homebrew/var/postgresql@18/postmaster.pid`


Copilot finished thinking
Copilot said: I'll search the repository to understand the

I'll search the repository to understand the relationship between account and account federation.Based on the code in the GitBucket repository, here's the relationship between Account and AccountFederation:
The Link Between Account and AccountFederation

AccountFederation serves as a mapping/linking table that connects external federated identities (from OIDC or SAML identity providers) to GitBucket's internal Account records.
Key Relationships:

One-to-Many Relationship: An Account can be linked to multiple federated identities through AccountFederation records. The AccountFederation table stores:
- issuer: The identity provider issuer
- subject: The unique subject identifier from the identity provider
- userName: The GitBucket username (links to Account.userName)
