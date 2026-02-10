package service.config;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import java.util.Map;
/**
 * Oidc Configuration for Confidential Client Type
 *
 * Oidc client security configs.
 */
public class OidcClientConfig {
    /**
     * Callback Url.
     */
    String callbackUrl;
    /**
     * Client Authentication Method.
     */
    ClientAuthenticationMethod clientAuthenticationMethod;
    /**
     * Custom Params.
     */
    Map<String, Object> customParams;
    /**
     * Disable PKCE.
     */
    boolean disablePkce;
    /**
     * Discovery Uri for the Client.
     */
    String discoveryUri;
    /**
     * Client ID.
     */
    String id;
    /**
     * Validity for the JWT Token created from SAML Response
     */
    String maxAge;
    /**
     * Max Clock Skew
     */
    String maxClockSkew;
    /**
     * Preferred Jws Algorithm.
     */
    String preferredJwsAlgorithm    ;
    /**
     * Prompt whether login/consent
     */
    String prompt;
    /**
     * Auth0 Client Secret Key.
     */
    String responseType;
    /**
     * Oidc Request Scopes.
     */
    String scope;
    /**
     * Client Secret.
     */
    String secret;
    /**
     * Server Url.
     */
    String serverUrl;
    /**
     * Validity for the Session in case of confidential clients
     */
    int sessionExpiry;
    /**
     * Tenant in case of Azure.
     */
    String tenant;
    /**
     * Validity for the JWT Token created from SAML Response
     */
    Integer tokenValidity;
    /**
     * IDP type (Example Google,Azure).
     */
    String type;
    /**
     * Use Nonce.
     */
    String useNonce;

        public OidcClientConfig() {
        }

    public OidcClientConfig(String callbackUrl, ClientAuthenticationMethod clientAuthenticationMethod, Map<String, Object> customParams, boolean disablePkce, String discoveryUri, String id, String maxAge, String maxClockSkew, String preferredJwsAlgorithm, String prompt, String responseType, String scope, String secret, String serverUrl, int sessionExpiry, String tenant, Integer tokenValidity, String type, String useNonce) {
        this.callbackUrl = callbackUrl;
        this.clientAuthenticationMethod = clientAuthenticationMethod;
        this.customParams = customParams;
        this.disablePkce = disablePkce;
        this.discoveryUri = discoveryUri;
        this.id = id;
        this.maxAge = maxAge;
        this.maxClockSkew = maxClockSkew;
        this.preferredJwsAlgorithm = preferredJwsAlgorithm;
        this.prompt = prompt;
        this.responseType = responseType;
        this.scope = scope;
        this.secret = secret;
        this.serverUrl = serverUrl;
        this.sessionExpiry = sessionExpiry;
        this.tenant = tenant;
        this.tokenValidity = tokenValidity;
        this.type = type;
        this.useNonce = useNonce;
    }

    public String getCallbackUrl() {
        return callbackUrl;
    }

    public ClientAuthenticationMethod getClientAuthenticationMethod() {
        return clientAuthenticationMethod;
    }

    public Map<String, Object> getCustomParams() {
        return customParams;
    }

    public boolean isDisablePkce() {
        return disablePkce;
    }


    public String getDiscoveryUri() {
        return discoveryUri;
    }

    public String getId() {
        return id;
    }

    public String getMaxAge() {
        return maxAge;
    }

    public String getMaxClockSkew() {
        return maxClockSkew;
    }

    public String getPreferredJwsAlgorithm() {
        return preferredJwsAlgorithm;
    }

    public String getPrompt() {
        return prompt;
    }

    public String getResponseType() {
        return responseType;
    }

    public String getScope() {
        return scope;
    }

    public String getSecret() {
        return secret;
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public int getSessionExpiry() {
        return sessionExpiry;
    }    

    public String getTenant() {
        return tenant;
    }

    public Integer getTokenValidity() {
        return tokenValidity;
    }

    public String getType() {
        return type;
    }

    public String getUseNonce() {
        return useNonce;
    }
}