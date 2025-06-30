
package model;

import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;

public class OktaSSOConfig {
  /** Okta Client ID for the service application. (Required) */
  @Getter @Setter private String clientId;

  /** Okta Client Secret for the API service application. (Required) */
  @Getter @Setter private String clientSecret;

  /** Okta Authorization Server Url. (Required) */
  @Getter private String authorizationServerURL;

  /** Okta client scopes. */
  @Getter @Setter private List<String> scopes = new ArrayList<>();

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append(OktaSSOConfig.class.getName())
        .append('@')
        .append(Integer.toHexString(System.identityHashCode(this)))
        .append('[');
    sb.append("clientId");
    sb.append('=');
    sb.append(((this.clientId == null) ? "<null>" : this.clientId));
    sb.append("clientSecret");
    sb.append('=');
    sb.append(((this.clientSecret == null) ? "<null>" : this.clientSecret));
    sb.append(',');
    sb.append("authorizationServerURL");
    sb.append('=');
    sb.append(((this.authorizationServerURL == null) ? "<null>" : this.authorizationServerURL));
    sb.append(',');
    sb.append(',');
    sb.append("scopes");
    sb.append('=');
    sb.append(((this.scopes == null) ? "<null>" : this.scopes));
    sb.append(',');
    if (sb.charAt((sb.length() - 1)) == ',') {
      sb.setCharAt((sb.length() - 1), ']');
    } else {
      sb.append(']');
    }
    return sb.toString();
  }
}