package service.config;

/**
 * Client Authentication Method.
 */
public enum ClientAuthenticationMethod {
    CLIENT_SECRET_BASIC("client_secret_basic"),
    CLIENT_SECRET_JWT("client_secret_jwt"),
    CLIENT_SECRET_POST("client_secret_post"),
    PRIVATE_KEY_JWT("private_key_jwt");

    private final String value;

    ClientAuthenticationMethod(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}