package service.config;

public class Idp {
    /**
     * Authority URL (deprecated, use entityId instead).
     */
    String authorityUrl;
    /**
     * Identity Provider Entity ID usually same as the SSO login URL.
     */
    String entityId;
    /**
     * X509 Certificate
     */
    String idpX509Certificate;
    /**
     * Name ID format for SAML assertions
     */
    String nameId;
    /**
     * SSO Login URL.
     */
    String ssoLoginUrl;
}

