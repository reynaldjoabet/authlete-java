package service.config;

import java.util.Map;

/**
 * This schema defines the Authentication Configuration.
 */
public class AuthenticationConfiguration {
	/**
	 * Authentication Authority
	 */
	String authority;
	/**
	 * Callback URL
	 */
	String callbackUrl;
	/**
	 * Client ID
	 */
	String clientId;
	/**
	 * Client Type
	 */
	ClientType clientType;
	/**
	 * Enable automatic redirect from the sign-in page to the configured SSO
	 * provider.
	 */
	Boolean enableAutoRedirect;
	/**
	 * Enable Self Sign Up
	 */
	Boolean enableSelfSignup;
	/**
	 * Force secure flag on session cookies even when not using HTTPS directly.
	 * Enable this when running behind a proxy/load balancer that handles SSL
	 * termination.
	 */
	Boolean forceSecureSessionCookie;
	/**
	 * Jwt Principal Claim
	 */
	String[] jwtPrincipalClaims;
	/**
	 * Jwt Principal Claim Mapping. Format: 'key:claim_name' where key must be
	 * 'username' or 'email'. Both username and email mappings are required.
	 */
	String[] jwtPrincipalClaimsMapping;
	/**
	 * JWT claim name that contains team/department information. For SAML SSO, this
	 * is the attribute name (e.g., 'department') from the SAML assertion. For JWT,
	 * this is the claim name in the JWT token. The value from this claim will be
	 * used to automatically assign users to matching teams in OpenMetadata during
	 * login.
	 */
	String jwtTeamClaimMapping;
	/**
	 * LDAP Configuration in case the Provider is LDAP
	 */
	LDAPConfiguration ldapConfiguration;
	/**
	 * Oidc Configuration for Confidential Client Type
	 */
	OidcClientConfig oidcConfiguration;
	AuthProvider provider;
	/**
	 * Custom OIDC Authentication Provider Name
	 */
	String providerName;
	/**
	 * List of Public Key URLs
	 */
	String[] publicKeyUrls;
	/**
	 * This is used by auth provider provide response as either id_token or code.
	 */
	ResponseType responseType;
	/**
	 * Saml Configuration that is applicable only when the provider is Saml
	 */
	SamlSSOClientConfig samlConfiguration;
	/**
	 * Token Validation Algorithm to use.
	 */
	TokenValidationAlgorithm tokenValidationAlgorithm;

	public AuthenticationConfiguration() {
		// Set default values for optional fields
		this.enableAutoRedirect = false;
		this.enableSelfSignup = false;
		this.forceSecureSessionCookie = false;
		this.tokenValidationAlgorithm = TokenValidationAlgorithm.ES256;
	}

	public String getAuthority() {
		return authority;
	}

	public String getCallbackUrl() {
		return callbackUrl;
	}

	public String getClientId() {
		return clientId;
	}

	public ClientType getClientType() {
		return clientType;
	}

	public Boolean getEnableAutoRedirect() {
		return enableAutoRedirect;
	}

	public Boolean getEnableSelfSignup() {
		return enableSelfSignup;
	}

	public Boolean getForceSecureSessionCookie() {
		return forceSecureSessionCookie;
	}

	public String[] getJwtPrincipalClaims() {
		return jwtPrincipalClaims;
	}

	public String[] getJwtPrincipalClaimsMapping() {
		return jwtPrincipalClaimsMapping;
	}

	public String getJwtTeamClaimMapping() {
		return jwtTeamClaimMapping;
	}

	public LDAPConfiguration getLdapConfiguration() {
		return ldapConfiguration;
	}

	public OidcClientConfig getOidcConfiguration() {
		return oidcConfiguration;
	}

	public AuthProvider getProvider() {
		return provider;
	}

	public String getProviderName() {
		return providerName;
	}

	public String[] getPublicKeyUrls() {
		return publicKeyUrls;
	}

	public ResponseType getResponseType() {
		return responseType;
	}

	public SamlSSOClientConfig getSamlConfiguration() {
		return samlConfiguration;
	}

	public TokenValidationAlgorithm getTokenValidationAlgorithm() {
		return tokenValidationAlgorithm;

	}

}
