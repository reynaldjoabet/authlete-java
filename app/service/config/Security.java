package service.config;

public class Security {
    /**
     * KeyStore Alias
     */
    String keyStoreAlias;
    /**
     * KeyStore File Path
     */
    String keyStoreFilePath;
    /**
     * KeyStore Password
     */
    String keyStorePassword;
    /**
     * Encrypt Name Id while sending requests from SP.
     */
    Boolean sendEncryptedNameId;
    /**
     * Sign the Authn Request while sending.
     */
    Boolean sendSignedAuthRequest;
    /**
     * Want the Metadata of this SP to be signed.
     */
    Boolean signSpMetadata;
    /**
     * Only accept valid signed and encrypted assertions if the relevant flags are set
     */
    Boolean strictMode;
    /**
     * Validity for the JWT Token created from SAML Response
     */
    Integer tokenValidity;
    /**
     * In case of strict mode whether to validate XML format.
     */
    Boolean validateXml;
    /**
     * SP requires the assertion received to be encrypted.
     */
    Boolean wantAssertionEncrypted;
    /**
     * SP requires the assertions received to be signed.
     */
    Boolean wantAssertionsSigned;
    /**
     * SP requires the messages received to be signed.
     */
    Boolean wantMessagesSigned;
}


