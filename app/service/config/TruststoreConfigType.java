package service.config;

/**
 * Truststore Type e.g. TrustAll, HostName, JVMDefault, CustomTrustStore.
 */
public enum TruststoreConfigType {
    CustomTrustStore,
    HostName,
    JVMDefault,
    TrustAll
}