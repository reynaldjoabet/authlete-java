package service.config;

/**
 * Token Validation Algorithm to use.
 */
public enum TokenValidationAlgorithm {
    ES256("ES256"),
    ES384("ES384"),
    ES512("ES512"),
    RS256("RS256"),
    RS384("RS384"),
    RS512("RS512");

    private final String value;

    TokenValidationAlgorithm(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}

