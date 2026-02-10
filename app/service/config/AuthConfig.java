package service.config;
/**
 * This schema defines the Auth Config.
 */
class AuthConfig {
    /**
     * Auth0 SSO Configuration
     */
    Auth0SSOClientConfig auth0;
    /**
     * Azure SSO Configuration
     */
    AzureSSOClientConfig azure;
    /**
     * Custom OIDC SSO Configuration
     */
    CustomOIDCSSOClientConfig customOidc;
    /**
     * Google SSO Configuration
     */
    GoogleSSOClientConfig google;
    /**
     * Okta SSO Configuration
     */
    OktaSSOClientConfig okta;
    /**
     * OpenMetadata SSO Configuration
     */
    OpenMetadataJWTClientConfig openmetadata;
}

/**
 * Auth0 SSO Configuration
 *
 * Auth0 SSO client security configs.
 */
class  Auth0SSOClientConfig {
    /**
     * Auth0 Client ID.
     */
    String clientId;
    /**
     * Auth0 Domain.
     */
    String domain;
    /**
     * Auth0 Client Secret Key.
     */
    String secretKey;
}

/**
 * Azure SSO Configuration
 *
 * Azure SSO Client security config to connect to OpenMetadata.
 */
class AzureSSOClientConfig {
    /**
     * Azure SSO Authority
     */
    String authority;
    /**
     * Azure Client ID.
     */
    String clientId;
    /**
     * Azure SSO client secret key
     */
    String clientSecret;
    /**
     * Azure Client ID.
     */
    String[] scopes;
}

/**
 * Custom OIDC SSO Configuration
 *
 * Custom OIDC SSO client security configs.
 */
class CustomOIDCSSOClientConfig {
    /**
     * Custom OIDC Client ID.
     */
    String clientId;
    /**
     * Custom OIDC Client Secret Key.
     */
    String secretKey;
    /**
     * Custom OIDC token endpoint.
     */
    String tokenEndpoint;
}

/**
 * Google SSO Configuration
 *
 * Google SSO client security configs.
 */
class GoogleSSOClientConfig {
    /**
     * Google SSO audience URL
     */
    String audience;
    /**
     * Google SSO client secret key path or contents.
     */
    String secretKey;
}

/**
 * Okta SSO Configuration
 *
 * Okta SSO client security configs.
 */
class OktaSSOClientConfig {
    /**
     * Okta Client ID.
     */
    String clientId;
    /**
     * Okta Service account Email.
     */
    String email;
    /**
     * Okta org url.
     */
    String orgURL;
    /**
     * Okta Private Key.
     */
    String privateKey;
    /**
     * Okta client scopes.
     */
    String[] scopes;
}

/**
 * OpenMetadata SSO Configuration
 *
 * openMetadataJWTClientConfig security configs.
 */
class  OpenMetadataJWTClientConfig {
    /**
     * OpenMetadata generated JWT token.
     */
    String jwtToken;
}
