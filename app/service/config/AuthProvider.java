package service.config;

/**
 * OpenMetadata Server Authentication Provider. Make sure configure same auth providers as
 * the one configured on OpenMetadata server.
 */
public enum AuthProvider {
    AUTH0("auth0"),
    AWS_COGNITO("aws-cognito"),
    AZURE("azure"),
    BASIC("basic"),
    CUSTOM_OIDC("custom-oidc"),
    GOOGLE("google"),
    LDAP("ldap"),
    OKTA("okta"),
    OPENMETADATA("openmetadata"),
    SAML("saml");

    private final String value;

    AuthProvider(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}

