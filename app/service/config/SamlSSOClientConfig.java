package service.config;
/**
 * Saml Configuration that is applicable only when the provider is Saml
 *
 * SAML SSO client security configs.
 */
public class SamlSSOClientConfig {
    /**
     * Get logs from the Library in debug mode
     */
    Boolean debugMode;
    Idp idp;
    Security security;
    SP sp;
}
