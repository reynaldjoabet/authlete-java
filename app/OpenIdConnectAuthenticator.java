
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.AccessTokenValidator;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles an OpenID Connect Authentication response as received by the
 * facilitator. In the case of an implicit flow, validates the ID Token and
 * extracts the elasticsearch user properties from it. In the case of an
 * authorization code flow, it first exchanges the code in the authentication
 * response for an ID Token at the token endpoint of the OpenID Connect
 * Provider.
 */
// https://github.com/SylvainJuge/elasticsearch/blob/c24cc0f54c216a5bff8e6b0e3ad2d09f7a3eb956/x-pack/plugin/security/src/main/java/org/elasticsearch/xpack/security/authc/oidc/OpenIdConnectAuthenticator.java#L44
class OpenIdConnectAuthenticator {

	private static final Logger logger = LoggerFactory.getLogger(OpenIdConnectAuthenticator.class);
	private final HttpClient httpClient;

	public OpenIdConnectAuthenticator() {
		this.httpClient = HttpClient.newHttpClient();
	}

	public OpenIdConnectAuthenticator(HttpClient httpClient) {
		this.httpClient = httpClient;
	}
}