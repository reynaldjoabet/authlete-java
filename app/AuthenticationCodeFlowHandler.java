
import static org.pac4j.core.util.CommonHelper.assertNotNull;
import static org.pac4j.core.util.CommonHelper.isNotEmpty;
import service.config.AuthenticationConfiguration;
import service.config.AuthorizerConfiguration;
import service.config.OidcClientConfig;
import com.fasterxml.jackson.core.type.TypeReference;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.core.util.HttpUtils;
import org.pac4j.oidc.client.AzureAd2Client;
import org.pac4j.oidc.client.GoogleOidcClient;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.AzureAd2OidcConfiguration;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.config.PrivateKeyJWTClientAuthnMethodConfig;
import org.pac4j.oidc.credentials.OidcCredentials;


public class AuthenticationCodeFlowHandler {
  private static final Collection<ClientAuthenticationMethod> SUPPORTED_METHODS =
      Arrays.asList(
          ClientAuthenticationMethod.CLIENT_SECRET_POST,
          ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
          ClientAuthenticationMethod.PRIVATE_KEY_JWT,
          ClientAuthenticationMethod.NONE);

  public static final String DEFAULT_PRINCIPAL_DOMAIN = "openmetadata.org";
  public static final String OIDC_CREDENTIAL_PROFILE = "oidcCredentialProfile";
  public static final String SESSION_REDIRECT_URI = "sessionRedirectUri";
  public static final String SESSION_USER_ID = "userId";
  public static final String SESSION_USERNAME = "username";
  public static final String REDIRECT_URI_KEY = "redirectUri";



private static class Holder {
    private static AuthenticationCodeFlowHandler instance;

    private static void initialize(
        AuthenticationConfiguration authenticationConfiguration,
        AuthorizerConfiguration authorizerConfiguration) {
      instance =
          new AuthenticationCodeFlowHandler(authenticationConfiguration, authorizerConfiguration);
    }
  }

  private OidcClient client;
  private List<String> claimsOrder;
  private Map<String, String> claimsMapping;
  private String teamClaimMapping;
  private String serverUrl;
  private ClientAuthentication clientAuthentication;
  private String principalDomain;
  private int tokenValidity;
  private String maxAge;
  private String promptType;
  private AuthenticationConfiguration authenticationConfiguration;
  private AuthorizerConfiguration authorizerConfiguration;

  private AuthenticationCodeFlowHandler(
      AuthenticationConfiguration authenticationConfiguration,
      AuthorizerConfiguration authorizerConfiguration) {
    // Assert oidcConfig and Callback Url
    CommonHelper.assertNotNull(
        "OidcConfiguration", authenticationConfiguration.getOidcConfiguration());
    CommonHelper.assertNotBlank(
        "CallbackUrl", authenticationConfiguration.getOidcConfiguration().getCallbackUrl());
    CommonHelper.assertNotBlank(
        "ServerUrl", authenticationConfiguration.getOidcConfiguration().getServerUrl());

    // Build Required Params
    this.authenticationConfiguration = authenticationConfiguration;
    this.authorizerConfiguration = authorizerConfiguration;
    initializeFields();
  }

  public static AuthenticationCodeFlowHandler getInstance(
      AuthenticationConfiguration authenticationConfiguration,
      AuthorizerConfiguration authorizerConfiguration) {
    if (Holder.instance == null) {
      synchronized (AuthenticationCodeFlowHandler.class) {
        if (Holder.instance == null) {
          Holder.initialize(authenticationConfiguration, authorizerConfiguration);
        }
      }
    }
    return Holder.instance;
  }

  public static AuthenticationCodeFlowHandler getInstance() {
    if (Holder.instance == null) {
      throw new IllegalStateException(
          "AuthenticationCodeFlowHandler is not initialized. Call getInstance() with configuration first.");
    }
    return Holder.instance;
  }

  public synchronized void updateConfiguration(
      AuthenticationConfiguration authenticationConfiguration,
      AuthorizerConfiguration authorizerConfiguration) {
    this.authenticationConfiguration = authenticationConfiguration;
    this.authorizerConfiguration = authorizerConfiguration;
    initializeFields();
  }

  private void initializeFields() {
    this.client = buildOidcClient(authenticationConfiguration.getOidcConfiguration());
    client.setCallbackUrl(authenticationConfiguration.getOidcConfiguration().getCallbackUrl());

    this.serverUrl = authenticationConfiguration.getOidcConfiguration().getServerUrl();
    this.claimsOrder = authenticationConfiguration.getJwtPrincipalClaims();
    this.claimsMapping =
        listOrEmpty(authenticationConfiguration.getJwtPrincipalClaimsMapping()).stream()
            .map(s -> s.split(":"))
            .collect(Collectors.toMap(s -> s[0], s -> s[1]));
    validatePrincipalClaimsMapping(claimsMapping);
    this.teamClaimMapping = authenticationConfiguration.getJwtTeamClaimMapping();
    this.principalDomain = authorizerConfiguration.getPrincipalDomain();
    this.tokenValidity = authenticationConfiguration.getOidcConfiguration().getTokenValidity();
    this.maxAge = authenticationConfiguration.getOidcConfiguration().getMaxAge();
    this.promptType = authenticationConfiguration.getOidcConfiguration().getPrompt();
    this.clientAuthentication = getClientAuthentication(client.getConfiguration());
  }

  private OidcClient buildOidcClient(OidcClientConfig clientConfig) {
    String id = clientConfig.getId();
    String secret = clientConfig.getSecret();
    if (CommonHelper.isNotBlank(id) && CommonHelper.isNotBlank(secret)) {
      OidcConfiguration configuration = new OidcConfiguration();
      configuration.setClientId(id);

      configuration.setResponseMode("query");

      // Add Secret
      if (CommonHelper.isNotBlank(secret)) {
        configuration.setSecret(secret);
      }

      // Response Type
      String responseType = clientConfig.getResponseType();
      if (CommonHelper.isNotBlank(responseType)) {
        configuration.setResponseType(responseType);
      }

      String scope = clientConfig.getScope();
      if (CommonHelper.isNotBlank(scope)) {
        configuration.setScope(scope);
      }

      String discoveryUri = clientConfig.getDiscoveryUri();
      if (CommonHelper.isNotBlank(discoveryUri)) {
        configuration.setDiscoveryURI(discoveryUri);
      }

      String useNonce = clientConfig.getUseNonce();
      if (CommonHelper.isNotBlank(useNonce)) {
        configuration.setUseNonce(Boolean.parseBoolean(useNonce));
      }

      String jwsAlgo = clientConfig.getPreferredJwsAlgorithm();
      if (CommonHelper.isNotBlank(jwsAlgo)) {
        configuration.setPreferredJwsAlgorithm(JWSAlgorithm.parse(jwsAlgo));
      }

      String maxClockSkew = clientConfig.getMaxClockSkew();
      if (CommonHelper.isNotBlank(maxClockSkew)) {
        configuration.setMaxClockSkew(Integer.parseInt(maxClockSkew));
      }

      String clientAuthenticationMethod = clientConfig.getClientAuthenticationMethod().value();
      if (CommonHelper.isNotBlank(clientAuthenticationMethod)) {
        configuration.setClientAuthenticationMethod(
            ClientAuthenticationMethod.parse(clientAuthenticationMethod));
      }

      // Disable PKCE
      configuration.setDisablePkce(clientConfig.getDisablePkce());

      // Add Custom Params
      if (clientConfig.getCustomParams() != null) {
        for (int j = 1; j <= 5; ++j) {
          if (clientConfig.getCustomParams().containsKey(String.format("customParamKey%d", j))) {
            configuration.addCustomParam(
                clientConfig.getCustomParams().get(String.format("customParamKey%d", j)),
                clientConfig.getCustomParams().get(String.format("customParamValue%d", j)));
          }
        }
      }

      String type = clientConfig.getType();
      OidcClient oidcClient;
      if ("azure".equalsIgnoreCase(type)) {
        AzureAd2OidcConfiguration azureAdConfiguration =
            new AzureAd2OidcConfiguration(configuration);
        String tenant = clientConfig.getTenant();
        if (CommonHelper.isNotBlank(tenant)) {
          azureAdConfiguration.setTenant(tenant);
        }

        oidcClient = new AzureAd2Client(azureAdConfiguration);
      } else if ("google".equalsIgnoreCase(type)) {
        oidcClient = new GoogleOidcClient(configuration);
        // Google needs it as param
        oidcClient.getConfiguration().getCustomParams().put("access_type", "offline");
      } else {
        oidcClient = new OidcClient(configuration);
      }

      oidcClient.setName(String.format("OMOidcClient%s", oidcClient.getName()));
      return oidcClient;
    }
    throw new IllegalArgumentException(
        "Client ID and Client Secret is required to create OidcClient");
  }




  private String buildLoginAuthenticationRequestUrl(final Map<String, String> params) {
    // Build authentication request query string
    String queryString;
    try {
      queryString =
          AuthenticationRequest.parse(
                  params.entrySet().stream()
                      .collect(
                          Collectors.toMap(
                              Map.Entry::getKey, e -> Collections.singletonList(e.getValue()))))
              .toQueryString();
    } catch (Exception e) {
      throw new TechnicalException(e);
    }
    return client.getConfiguration().getProviderMetadata().getAuthorizationEndpointURI().toString()
        + '?'
        + queryString;
  }

  private Map<String, String> buildLoginParams() {
    Map<String, String> authParams = new HashMap<>();
    authParams.put(OidcConfiguration.SCOPE, client.getConfiguration().getScope());
    authParams.put(OidcConfiguration.RESPONSE_TYPE, client.getConfiguration().getResponseType());
    authParams.put(OidcConfiguration.RESPONSE_MODE, "query");
    authParams.putAll(client.getConfiguration().getCustomParams());
    authParams.put(OidcConfiguration.CLIENT_ID, client.getConfiguration().getClientId());

    return new HashMap<>(authParams);
  }




  private OidcCredentials buildCredentials(AuthenticationSuccessResponse successResponse) {
    OidcCredentials credentials = new OidcCredentials();
    // get authorization code
    AuthorizationCode code = successResponse.getAuthorizationCode();
    if (code != null) {
      credentials.setCode(code);
    }
    // get ID token
    JWT idToken = successResponse.getIDToken();
    if (idToken != null) {
      credentials.setIdToken(idToken);
    }
    // get access token
    AccessToken accessToken = successResponse.getAccessToken();
    if (accessToken != null) {
      credentials.setAccessToken(accessToken);
    }

    return credentials;
  }

  private ClientAuthentication getClientAuthentication(OidcConfiguration configuration) {
    ClientID clientID = new ClientID(configuration.getClientId());
    ClientAuthentication clientAuthenticationMechanism = null;
    if (configuration.getSecret() != null) {
      // check authentication methods
      List<ClientAuthenticationMethod> metadataMethods =
          configuration.findProviderMetadata().getTokenEndpointAuthMethods();

      ClientAuthenticationMethod preferredMethod = getPreferredAuthenticationMethod(configuration);

      final ClientAuthenticationMethod chosenMethod;
      if (isNotEmpty(metadataMethods)) {
        if (preferredMethod != null) {
          if (metadataMethods.contains(preferredMethod)) {
            chosenMethod = preferredMethod;
          } else {
            throw new TechnicalException(
                "Preferred authentication method ("
                    + preferredMethod
                    + ") not supported "
                    + "by provider according to provider metadata ("
                    + metadataMethods
                    + ").");
          }
        } else {
          chosenMethod = firstSupportedMethod(metadataMethods);
        }
      } else {
        chosenMethod =
            preferredMethod != null ? preferredMethod : ClientAuthenticationMethod.getDefault();
        LOG.info(
            "Provider metadata does not provide Token endpoint authentication methods. Using: {}",
            chosenMethod);
      }

      if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(chosenMethod)) {
        Secret clientSecret = new Secret(configuration.getSecret());
        clientAuthenticationMechanism = new ClientSecretPost(clientID, clientSecret);
      } else if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(chosenMethod)) {
        Secret clientSecret = new Secret(configuration.getSecret());
        clientAuthenticationMechanism = new ClientSecretBasic(clientID, clientSecret);
      } else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(chosenMethod)) {
        PrivateKeyJWTClientAuthnMethodConfig privateKetJwtConfig =
            configuration.getPrivateKeyJWTClientAuthnMethodConfig();
        assertNotNull("privateKetJwtConfig", privateKetJwtConfig);
        JWSAlgorithm jwsAlgo = privateKetJwtConfig.getJwsAlgorithm();
        assertNotNull("privateKetJwtConfig.getJwsAlgorithm()", jwsAlgo);
        PrivateKey privateKey = privateKetJwtConfig.getPrivateKey();
        assertNotNull("privateKetJwtConfig.getPrivateKey()", privateKey);
        String keyID = privateKetJwtConfig.getKeyID();
        try {
          clientAuthenticationMechanism =
              new PrivateKeyJWT(
                  clientID,
                  configuration.findProviderMetadata().getTokenEndpointURI(),
                  jwsAlgo,
                  privateKey,
                  keyID,
                  null);
        } catch (final JOSEException e) {
          throw new TechnicalException(
              "Cannot instantiate private key JWT client authentication method", e);
        }
      }
    }

    return clientAuthenticationMechanism;
  }

  private static ClientAuthenticationMethod getPreferredAuthenticationMethod(
      OidcConfiguration config) {
    ClientAuthenticationMethod configurationMethod = config.getClientAuthenticationMethod();
    if (configurationMethod == null) {
      return null;
    }

    if (!SUPPORTED_METHODS.contains(configurationMethod)) {
      throw new TechnicalException(
          "Configured authentication method (" + configurationMethod + ") is not supported.");
    }

    return configurationMethod;
  }

  private ClientAuthenticationMethod firstSupportedMethod(
      final List<ClientAuthenticationMethod> metadataMethods) {
    Optional<ClientAuthenticationMethod> firstSupported =
        metadataMethods.stream().filter(SUPPORTED_METHODS::contains).findFirst();
    if (firstSupported.isPresent()) {
      return firstSupported.get();
    } else {
      throw new TechnicalException(
          "None of the Token endpoint provider metadata authentication methods are supported: "
              + metadataMethods);
    }
  }


  private Set<String> getAdminPrincipals() {
    return new HashSet<>(authorizerConfiguration.getAdminPrincipals());
  }

  public static boolean isJWT(String token) {
    return token.split("\\.").length == 3;
  }

  private void refreshAccessTokenAzureAd2Token(
      AzureAd2OidcConfiguration azureConfig, OidcCredentials azureAdProfile) {

    HttpURLConnection connection = null;
    try {
      RefreshToken refreshToken = azureAdProfile.getRefreshToken();
      if (refreshToken == null || refreshToken.getValue() == null) {
        throw new TechnicalException("No refresh token available to request new access token.");
      }

      Map<String, String> headers = new HashMap<>();
      headers.put(
          HttpConstants.CONTENT_TYPE_HEADER, HttpConstants.APPLICATION_FORM_ENCODED_HEADER_VALUE);
      headers.put(HttpConstants.ACCEPT_HEADER, HttpConstants.APPLICATION_JSON);

      URL tokenEndpointURL = azureConfig.findProviderMetadata().getTokenEndpointURI().toURL();
      connection = HttpUtils.openPostConnection(tokenEndpointURL, headers);

      String requestBody = azureConfig.makeOauth2TokenRequest(refreshToken.getValue());
      byte[] bodyBytes = requestBody.getBytes(StandardCharsets.UTF_8);
      connection.setFixedLengthStreamingMode(bodyBytes.length);

      try (BufferedWriter out =
          new BufferedWriter(
              new OutputStreamWriter(connection.getOutputStream(), StandardCharsets.UTF_8))) {
        out.write(requestBody);
      }

      int responseCode = connection.getResponseCode();
      if (responseCode != 200) {
        String error = HttpUtils.buildHttpErrorMessage(connection);
        LOG.warn("Token refresh failed ({}): {}", responseCode, error);
        throw new TechnicalException("Token refresh failed with status: " + responseCode);
      }

      String body = HttpUtils.readBody(connection);
      Map<String, Object> res = JsonUtils.readValue(body, new TypeReference<>() {});

      azureAdProfile.setAccessToken(new BearerAccessToken((String) res.get("access_token")));
      azureAdProfile.setRefreshToken(new RefreshToken((String) res.get("refresh_token")));

      if (res.containsKey("id_token")) {
        azureAdProfile.setIdToken(SignedJWT.parse((String) res.get("id_token")));
      }

    } catch (IOException | ParseException e) {
      throw new TechnicalException("Exception while refreshing Azure AD token", e);
    } finally {
      HttpUtils.closeConnection(connection);
    }
  }

  public static void validatePrincipalClaimsMapping(Map<String, String> mapping) {
    if (!nullOrEmpty(mapping)) {
      String username = mapping.get(USERNAME_CLAIM_KEY);
      String email = mapping.get(EMAIL_CLAIM_KEY);

      // Validate that both username and email are present
      if (nullOrEmpty(username) || nullOrEmpty(email)) {
        throw new IllegalArgumentException(
            "Invalid JWT Principal Claims Mapping. Both username and email should be present");
      }
    }
    // If emtpy, jwtPrincipalClaims will be used so no need to validate
  }

  private HTTPResponse executeTokenHttpRequest(TokenRequest request) throws IOException {
    HTTPRequest tokenHttpRequest = request.toHTTPRequest();
    client.getConfiguration().configureHttpRequest(tokenHttpRequest);

    HTTPResponse httpResponse = tokenHttpRequest.send();
    LOG.debug(
        "Token response: status={}, content={}",
        httpResponse.getStatusCode(),
        httpResponse.getContent());

    return httpResponse;
  }

  private TokenRequest createTokenRequest(final AuthorizationGrant grant) {
    if (clientAuthentication != null) {
      return new TokenRequest(
          client.getConfiguration().findProviderMetadata().getTokenEndpointURI(),
          this.clientAuthentication,
          grant);
    } else {
      return new TokenRequest(
          client.getConfiguration().findProviderMetadata().getTokenEndpointURI(),
          new ClientID(client.getConfiguration().getClientId()),
          grant);
    }
  }


  private void populateCredentialsFromTokenResponse(
      OIDCTokenResponse tokenSuccessResponse, OidcCredentials credentials) {
    OIDCTokens oidcTokens = tokenSuccessResponse.getOIDCTokens();
    credentials.setAccessToken(oidcTokens.getAccessToken());
    if (oidcTokens.getRefreshToken() != null) {
      credentials.setRefreshToken(oidcTokens.getRefreshToken());
    }
    if (oidcTokens.getIDToken() != null) {
      credentials.setIdToken(oidcTokens.getIDToken());
    }
  }

  private OIDCTokenResponse parseTokenResponseFromHttpResponse(HTTPResponse httpResponse)
      throws com.nimbusds.oauth2.sdk.ParseException {
    TokenResponse response = OIDCTokenResponseParser.parse(httpResponse);
    if (response instanceof TokenErrorResponse tokenErrorResponse) {
      ErrorObject errorObject = tokenErrorResponse.getErrorObject();
      throw new TechnicalException(
          "Bad token response, error="
              + errorObject.getCode()
              + ","
              + " description="
              + errorObject.getDescription());
    }
    LOG.debug("Token response successful");
    return (OIDCTokenResponse) response;
  }

  public static void validateConfig(
      AuthenticationConfiguration authConfig, AuthorizerConfiguration authzConfig) {
    try {
      // Create a temporary handler just for validation
      AuthenticationCodeFlowHandler tempHandler =
          new AuthenticationCodeFlowHandler(authConfig, authzConfig);

      // Validate required configurations
      CommonHelper.assertNotNull("OidcConfiguration", authConfig.getOidcConfiguration());
      CommonHelper.assertNotBlank(
          "CallbackUrl", authConfig.getOidcConfiguration().getCallbackUrl());
      CommonHelper.assertNotBlank("ServerUrl", authConfig.getOidcConfiguration().getServerUrl());

      // Use the temporary handler's client to validate
      if (tempHandler.client == null) {
        throw new IllegalArgumentException("Failed to initialize OIDC client");
      }

      // Validate provider metadata
      OIDCProviderMetadata providerMetadata =
          tempHandler.client.getConfiguration().findProviderMetadata();
      if (providerMetadata == null) {
        throw new IllegalArgumentException("Failed to retrieve provider metadata from server URL");
      }

      // Validate required endpoints
      if (providerMetadata.getAuthorizationEndpointURI() == null) {
        throw new IllegalArgumentException("Authorization endpoint not found in provider metadata");
      }

      if (providerMetadata.getTokenEndpointURI() == null) {
        throw new IllegalArgumentException("Token endpoint not found in provider metadata");
      }

    } catch (Exception e) {
      throw new IllegalArgumentException(
          "OIDC configuration validation failed: " + e.getMessage(), e);
    }
  }
}