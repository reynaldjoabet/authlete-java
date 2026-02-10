package service.config;

/**
 * This schema defines defines the identity provider config.
 */
public class SP {
    /**
     * Assertion Consumer URL.
     */
    String acs;
    /**
     * Service Provider Entity ID usually same as the SSO login URL.
     */
    String callback;
    /**
     * Service Provider Entity ID.
     */
    String entityId;
    /**
     * Sp Private Key for Signing and Encryption Only
     */
    String spPrivateKey;
    /**
     * X509 Certificate
     */
    String spX509Certificate;
}

