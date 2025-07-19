package models;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.HashMap;
import java.util.Map;

public class AccessTokenResponse {
  @JsonProperty("token_type")
  private String tokenType = null;

  @JsonProperty("expires_in")
  private Long expiresIn = null;

  @JsonProperty("access_token")
  private String accessToken = null;

  @JsonProperty("scope")
  private String scope = null;

  /**
   * Get TokenType
   *
   * @return TokenType
   */
  @Schema(description = "")
  public String getTokenType() {
    return tokenType;
  }

  public void setTokenType(String description) {
    this.tokenType = description;
  }

  public AccessTokenResponse withTokenType(String displayName) {
    this.tokenType = displayName;
    return this;
  }

  /**
   * Get ExpiresIn
   *
   * @return ExpiresIn
   */
  @Schema()
  public Long getExpiresIn() {
    return expiresIn;
  }

  public void setExpiresIn(Long iExpiresIn) {
    this.expiresIn = iExpiresIn;
  }

  public AccessTokenResponse withExpiresIn(Long iExpiresIn) {
    this.expiresIn = iExpiresIn;
    return this;
  }

  /**
   * Get AccessToken
   *
   * @return AccessToken
   */
  @Schema()
  public String getAccessToken() {
    return accessToken;
  }

  public void setAccessToken(String iAccessToken) {
    this.accessToken = iAccessToken;
  }

  public AccessTokenResponse withAccessToken(String iAccessToken) {
    this.accessToken = iAccessToken;
    return this;
  }

  /**
   * Get Scope
   *
   * @return Scope
   */
  @Schema()
  public String getScope() {
    return scope;
  }

  public void setScope(String iScopes) {
    this.scope = iScopes;
  }

  public AccessTokenResponse withScope(String iScopes) {
    this.scope = iScopes;
    return this;
  }

  public enum GrantType {
    AUTHORIZATION_CODE("authorization_code"),
    CLIENT_CREDENTIALS("client_credentials"),
    IMPLICIT("implicit");
    private final String value;
    private static final Map<String, AccessTokenResponse.GrantType> CONSTANTS = new HashMap<>();

    static {
      for (AccessTokenResponse.GrantType c : values()) {
        CONSTANTS.put(c.value, c);
      }
    }

    GrantType(String value) {
      this.value = value;
    }

    @Override
    public String toString() {
      return this.value;
    }

    public String value() {
      return this.value;
    }

    public static AccessTokenResponse.GrantType fromValue(String value) {
      AccessTokenResponse.GrantType constant = CONSTANTS.get(value);
      if (constant == null) {
        throw new IllegalArgumentException(value);
      } else {
        return constant;
      }
    }
  }
}