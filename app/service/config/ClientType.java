package service.config;

/**
 * Client Type
 */
public enum ClientType {
    CONFIDENTIAL("confidential"),
    PUBLIC("public");

    private final String value;

    ClientType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}