package service.config;
/**
 * LDAP Configuration
 */
public class LDAPConfiguration {
    /**
     * All attribute name
     */
    String allAttributeName;
    /**
     * Roles should be reassign every time user login
     */
    String[] authReassignRoles;
    /**
     * Json string of roles mapping between LDAP roles and Ranger roles
     */
    String authRolesMapping;
    /**
     * Password for LDAP Admin
     */
    String dnAdminPassword;
    /**
     * Distinguished Admin name with search capabilities
     */
    String dnAdminPrincipal;
    /**
     * Group Name attribute name
     */
    String groupAttributeName;
    /**
     * Group attribute value
     */
    String groupAttributeValue;
    /**
     * Group base distinguished name
     */
    String groupBaseDN;
    /**
     * Group Member Name attribute name
     */
    String groupMemberAttributeName;
    /**
     * LDAP server address without scheme(Example :- localhost)
     */
    String host;
    /**
     * If enable need to give full dn to login
     */
    Boolean isFullDn;
    /**
     * Email attribute name
     */
    String mailAttributeName;
    /**
     * No of connection to create the pool with
     */
    Integer maxPoolSize;
    /**
     * Port of the server
     */
    Integer port;
    /**
     * Admin role name
     */
    String roleAdminName;
    /**
     * LDAPS (secure LDAP) or LDAP
     */
    Boolean sslEnabled;
    /**
     * Truststore Configuration
     */
    TruststoreConfig trustStoreConfig;
    /**
     * Truststore Type e.g. TrustAll, HostName, JVMDefault, CustomTrustStore.
     */
    TruststoreConfigType truststoreConfigType;
    /**
     * Truststore format e.g. PKCS12, JKS.
     */
    String truststoreFormat;
    /**
     * User base distinguished name
     */
    String userBaseDN;
    /**
     * User Name attribute name
     */
    String usernameAttributeName;
}

