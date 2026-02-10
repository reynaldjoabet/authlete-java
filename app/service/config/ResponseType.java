package service.config;

/**
 * Response Type
 */
public enum ResponseType {
    CODE("code"),
    ID_TOKEN("id_token");

    private final String value;

    ResponseType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}



