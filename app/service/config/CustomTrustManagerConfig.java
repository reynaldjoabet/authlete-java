package service.config;

/**
 * CustomTrust Configuration
 */
public class CustomTrustManagerConfig {
    /**
     * Examine validity dates of certificate
     */
    boolean examineValidityDates;
    /**
     * Truststore file format
     */
    String trustStoreFileFormat;
    /**
     * Truststore file password
     */
    String trustStoreFilePassword;
    /**
     * Truststore file path
     */
    String trustStoreFilePath;
    /**
     * list of host names to verify
     */
    boolean verifyHostname;
}
