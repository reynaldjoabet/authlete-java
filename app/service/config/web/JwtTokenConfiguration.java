package service.config;
/**
 * This schema defines the JWT Configuration.
 */
class JwtTokenConfiguration {
    /**
     * JWT Issuer
     */
    String jwtissuer;
    /**
     * Key ID
     */
    String keyId;
    /**
     * RSA Private Key File Path
     */
    String rsaprivateKeyFilePath;
    /**
     * RSA Public Key File Path
     */
    String rsapublicKeyFilePath;
}
