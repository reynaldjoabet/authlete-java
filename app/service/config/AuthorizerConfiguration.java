package service.config;
/**
 * This schema defines the Authorization Configuration.
 */
public class AuthorizerConfiguration {
    /**
     * List of unique admin principals.
     */
    String[] adminPrincipals;
    /**
     * Allowed Domains to access
     */
    String[] allowedDomains;
    /**
     * List of unique email domains that are allowed to signup on the platforms
     */
    String[] allowedEmailRegistrationDomains;
    /**
     * **@Deprecated** List of unique bot principals
     */
    String[] botPrincipals;
    /**
     * Class Name for authorizer.
     */
    String className;
    /**
     * Filter for the request authorization.
     */
    String containerRequestFilter;
    /**
     * Enable Secure Socket Connection.
     */
    boolean enableSecureSocketConnection;
    /**
     * Enable Enforce Principal Domain
     */
    boolean enforcePrincipalDomain;
    /**
     * Principal Domain
     */
    String principalDomain;
    /**
     * List of unique principals used as test users. **NOTE THIS IS ONLY FOR TEST SETUP AND NOT
     * TO BE USED IN PRODUCTION SETUP**
     */
    String[] testPrincipals;
    /**
     * Use Roles from Provider
     */
    boolean useRolesFromProvider;
}
