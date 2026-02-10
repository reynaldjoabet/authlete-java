package auth.controllers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.typesafe.config.Config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.EnumSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import javax.inject.Inject;
import javax.inject.Singleton;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import play.libs.typedmap.TypedKey;
import play.mvc.Http.Request;
import play.mvc.Http.Status;

/**
 * JWT Verifier for secure token validation and creation.
 * 
 * <p>
 * Features:
 * <ul>
 * <li>Support for both HMAC (HS256/HS384/HS512) and RSA (RS256/RS384/RS512)
 * algorithms</li>
 * <li>Token blacklisting for logout/revocation</li>
 * <li>Configurable expiration and clock skew tolerance</li>
 * <li>Issuer and audience validation</li>
 * <li>Thread-safe token caching</li>
 * <li>Comprehensive error handling and logging</li>
 * </ul>
 */
@Singleton
@Slf4j
public class JWTVerifier {

	// TypedKeys for request attributes
	public static final TypedKey<ClientType> CLIENT_TYPE_CLAIM = TypedKey.create("clientType");
	public static final TypedKey<UUID> CLIENT_ID_CLAIM = TypedKey.create("clientId");
	public static final TypedKey<UUID> USER_ID_CLAIM = TypedKey.create("userId");

	// Claim names
	private static final String CLAIM_CLIENT_TYPE = "clientType";
	private static final String CLAIM_CLIENT_ID = "clientId";
	private static final String CLAIM_USER_ID = "userId";
	private static final String CLAIM_ROLES = "roles";
	private static final String CLAIM_PERMISSIONS = "permissions";

	// Configuration keys
	private static final String CONFIG_SECRET_KEY = "play.http.secret.key";
	private static final String CONFIG_JWT_ISSUER = "jwt.issuer";
	private static final String CONFIG_JWT_AUDIENCE = "jwt.audience";
	private static final String CONFIG_JWT_EXPIRATION = "jwt.expiration";
	private static final String CONFIG_JWT_CLOCK_SKEW = "jwt.clockSkew";
	private static final String CONFIG_JWT_ALGORITHM = "jwt.algorithm";

	// Defaults
	private static final Duration DEFAULT_EXPIRATION = Duration.ofHours(1);
	private static final Duration DEFAULT_CLOCK_SKEW = Duration.ofMinutes(5);
	private static final String DEFAULT_ISSUER = "authlete-java";
	private static final String DEFAULT_AUDIENCE = "authlete-api";
	private static final JWSAlgorithm DEFAULT_ALGORITHM = JWSAlgorithm.HS256;

	// State
	private final JWSSigner signer;
	private final JWSVerifier verifier;
	private final JWSAlgorithm algorithm;
	private final String issuer;
	private final String audience;
	private final Duration expiration;
	private final Duration clockSkew;
	private final Clock clock;

	// Blacklist for revoked tokens (jti -> expiration time)
	private final Map<String, Instant> tokenBlacklist = new ConcurrentHashMap<>();

	/**
	 * Client type enumeration for API authentication.
	 */
	public enum ClientType {
		/** Confidential client that can securely store credentials */
		CONFIDENTIAL("confidential"),
		/** Public client (e.g., SPA, mobile app) */
		PUBLIC("public"),
		/** Service-to-service communication */
		SERVICE("service");

		private final String value;

		ClientType(String value) {
			this.value = value;
		}

		public String getValue() {
			return value;
		}

		public static Optional<ClientType> fromString(String value) {
			if (value == null) {
				return Optional.empty();
			}
			for (ClientType type : values()) {
				if (type.value.equalsIgnoreCase(value)) {
					return Optional.of(type);
				}
			}
			return Optional.empty();
		}
	}

	/**
	 * Result of JWT verification.
	 */
	public sealed interface VerificationResult permits VerificationResult.Success,VerificationResult.Failure {

		record Success(JWTClaims claims) implements VerificationResult {
		}

		record Failure(ErrorCode code, String message) implements VerificationResult {
			public int getStatusCode() {
				return code.getHttpStatus();
			}
		}
	}

	/**
	 * Error codes for JWT verification failures.
	 */
	public enum ErrorCode {
		MISSING_TOKEN(Status.UNAUTHORIZED, "Authorization token is required"),
		INVALID_FORMAT(Status.BAD_REQUEST, "Invalid token format"),
		INVALID_SIGNATURE(Status.UNAUTHORIZED, "Token signature verification failed"),
		EXPIRED_TOKEN(Status.UNAUTHORIZED, "Token has expired"),
		NOT_YET_VALID(Status.UNAUTHORIZED, "Token is not yet valid"),
		INVALID_ISSUER(Status.UNAUTHORIZED, "Invalid token issuer"),
		INVALID_AUDIENCE(Status.UNAUTHORIZED, "Invalid token audience"),
		REVOKED_TOKEN(Status.UNAUTHORIZED, "Token has been revoked"),
		MISSING_CLAIMS(Status.BAD_REQUEST, "Required claims are missing"),
		INTERNAL_ERROR(Status.INTERNAL_SERVER_ERROR, "Internal authentication error");

		private final int httpStatus;
		private final String defaultMessage;

		ErrorCode(int httpStatus, String defaultMessage) {
			this.httpStatus = httpStatus;
			this.defaultMessage = defaultMessage;
		}

		public int getHttpStatus() {
			return httpStatus;
		}

		public String getDefaultMessage() {
			return defaultMessage;
		}
	}

	/**
	 * Parsed and validated JWT claims.
	 */
	public record JWTClaims(String jti, UUID userId, UUID clientId, ClientType clientType, Set<String> roles,
			Set<String> permissions, Instant issuedAt, Instant expiresAt, Map<String, Object> additionalClaims) {
		public boolean hasRole(String role) {
			return roles != null && roles.contains(role);
		}

		public boolean hasPermission(String permission) {
			return permissions != null && permissions.contains(permission);
		}

		public boolean hasAnyRole(String... checkRoles) {
			if (roles == null)
				return false;
			for (String role : checkRoles) {
				if (roles.contains(role))
					return true;
			}
			return false;
		}
	}

	@Inject
	public JWTVerifier(Config config) {
		this(config, Clock.systemUTC());
	}

	/**
	 * Constructor with injectable clock for testing.
	 */
	public JWTVerifier(Config config, Clock clock) {
		this.clock = clock;
		this.issuer = getConfigString(config, CONFIG_JWT_ISSUER, DEFAULT_ISSUER);
		this.audience = getConfigString(config, CONFIG_JWT_AUDIENCE, DEFAULT_AUDIENCE);
		this.expiration = getConfigDuration(config, CONFIG_JWT_EXPIRATION, DEFAULT_EXPIRATION);
		this.clockSkew = getConfigDuration(config, CONFIG_JWT_CLOCK_SKEW, DEFAULT_CLOCK_SKEW);
		this.algorithm = parseAlgorithm(getConfigString(config, CONFIG_JWT_ALGORITHM, DEFAULT_ALGORITHM.getName()));

		try {
			if (isHmacAlgorithm(algorithm)) {
				byte[] secret = getOrGenerateSecret(config);
				this.signer = new MACSigner(secret);
				this.verifier = new MACVerifier(secret);
			} else if (isRsaAlgorithm(algorithm)) {
				KeyPair keyPair = generateRsaKeyPair();
				this.signer = new RSASSASigner((RSAPrivateKey) keyPair.getPrivate());
				this.verifier = new RSASSAVerifier((RSAPublicKey) keyPair.getPublic());
			} else {
				throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
			}
			log.info("JWTVerifier initialized with algorithm={}, issuer={}, expiration={}", algorithm.getName(), issuer,
					expiration);
		} catch (JOSEException e) {
			log.error("Failed to initialize JWTVerifier", e);
			throw new RuntimeException("JWT initialization failed", e);
		}
	}

	/**
	 * Create a new JWT token for the given user.
	 *
	 * @param userId      The user's unique identifier
	 * @param clientId    The client's unique identifier
	 * @param clientType  The type of client
	 * @param roles       The user's roles
	 * @param permissions The user's permissions
	 * @return The signed JWT token string
	 */
	public String createToken(UUID userId, UUID clientId, ClientType clientType, Set<String> roles,
			Set<String> permissions) {
		return createToken(userId, clientId, clientType, roles, permissions, Map.of());
	}

	/**
	 * Create a new JWT token with additional custom claims.
	 */
	public String createToken(UUID userId, UUID clientId, ClientType clientType, Set<String> roles,
			Set<String> permissions, Map<String, Object> additionalClaims) {
		Instant now = clock.instant();
		String jti = UUID.randomUUID().toString();

		JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder().jwtID(jti).issuer(issuer).audience(audience)
				.subject(userId != null ? userId.toString() : null).issueTime(Date.from(now)).notBefore(Date.from(now))
				.expirationTime(Date.from(now.plus(expiration)))
				.claim(CLAIM_USER_ID, userId != null ? userId.toString() : null)
				.claim(CLAIM_CLIENT_ID, clientId != null ? clientId.toString() : null)
				.claim(CLAIM_CLIENT_TYPE, clientType != null ? clientType.getValue() : null).claim(CLAIM_ROLES, roles)
				.claim(CLAIM_PERMISSIONS, permissions);

		additionalClaims.forEach(claimsBuilder::claim);

		JWTClaimsSet claimsSet = claimsBuilder.build();

		try {
			SignedJWT signedJWT = new SignedJWT(new JWSHeader(algorithm), claimsSet);
			signedJWT.sign(signer);

			log.debug("Created JWT token for userId={}, clientId={}, jti={}", userId, clientId, jti);
			return signedJWT.serialize();
		} catch (JOSEException e) {
			log.error("Failed to sign JWT token", e);
			throw new RuntimeException("Token creation failed", e);
		}
	}

	/**
	 * Create a simple token with just user ID.
	 */
	public String createToken(UUID userId) {
		return createToken(userId, null, ClientType.PUBLIC, Set.of(), Set.of());
	}

	/**
	 * Verify a JWT token and extract claims.
	 *
	 * @param token The JWT token string
	 * @return VerificationResult containing either Success with claims or Failure
	 *         with error
	 */
	public VerificationResult verify(String token) {
		if (StringUtils.isBlank(token)) {
			return new VerificationResult.Failure(ErrorCode.MISSING_TOKEN, "Token is null or empty");
		}

		// Remove "Bearer " prefix if present
		String cleanToken = token.startsWith("Bearer ") ? token.substring(7).trim() : token.trim();

		try {
			SignedJWT signedJWT = SignedJWT.parse(cleanToken);

			// Verify signature
			if (!signedJWT.verify(verifier)) {
				log.warn("JWT signature verification failed");
				return new VerificationResult.Failure(ErrorCode.INVALID_SIGNATURE, "Signature verification failed");
			}

			JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

			// Check if token is blacklisted
			String jti = claims.getJWTID();
			if (jti != null && isTokenBlacklisted(jti)) {
				log.warn("Attempted use of revoked token: jti={}", jti);
				return new VerificationResult.Failure(ErrorCode.REVOKED_TOKEN, "Token has been revoked");
			}

			// Validate expiration
			Date expirationTime = claims.getExpirationTime();
			if (expirationTime != null) {
				Instant expiry = expirationTime.toInstant();
				if (clock.instant().isAfter(expiry.plus(clockSkew))) {
					log.debug("JWT token expired at {}", expiry);
					return new VerificationResult.Failure(ErrorCode.EXPIRED_TOKEN, "Token expired at " + expiry);
				}
			}

			// Validate not before
			Date notBefore = claims.getNotBeforeTime();
			if (notBefore != null) {
				Instant nbf = notBefore.toInstant();
				if (clock.instant().isBefore(nbf.minus(clockSkew))) {
					log.debug("JWT token not yet valid, nbf={}", nbf);
					return new VerificationResult.Failure(ErrorCode.NOT_YET_VALID, "Token not valid until " + nbf);
				}
			}

			// Validate issuer
			String tokenIssuer = claims.getIssuer();
			if (!issuer.equals(tokenIssuer)) {
				log.warn("Invalid token issuer: expected={}, actual={}", issuer, tokenIssuer);
				return new VerificationResult.Failure(ErrorCode.INVALID_ISSUER, "Invalid issuer");
			}

			// Validate audience
			var audiences = claims.getAudience();
			if (audiences == null || !audiences.contains(audience)) {
				log.warn("Invalid token audience: expected={}, actual={}", audience, audiences);
				return new VerificationResult.Failure(ErrorCode.INVALID_AUDIENCE, "Invalid audience");
			}

			// Extract and build claims
			JWTClaims jwtClaims = extractClaims(claims);

			log.debug("Successfully verified JWT for userId={}", jwtClaims.userId());
			return new VerificationResult.Success(jwtClaims);

		} catch (ParseException e) {
			log.warn("Failed to parse JWT token: {}", e.getMessage());
			return new VerificationResult.Failure(ErrorCode.INVALID_FORMAT, "Invalid token format: " + e.getMessage());
		} catch (JOSEException e) {
			log.error("JWT verification error", e);
			return new VerificationResult.Failure(ErrorCode.INTERNAL_ERROR, "Verification error: " + e.getMessage());
		} catch (Exception e) {
			log.error("Unexpected error during JWT verification", e);
			return new VerificationResult.Failure(ErrorCode.INTERNAL_ERROR, "Internal error");
		}
	}

	/**
	 * Verify token from HTTP request Authorization header.
	 */
	public VerificationResult verifyRequest(Request request) {
		Optional<String> authHeader = request.header("Authorization");

		if (authHeader.isEmpty()) {
			// Try cookie-based token
			Optional<String> cookieToken = request.cookie("authToken").map(cookie -> cookie.value());

			if (cookieToken.isEmpty()) {
				return new VerificationResult.Failure(ErrorCode.MISSING_TOKEN, "No authorization token found");
			}

			return verify(cookieToken.get());
		}

		return verify(authHeader.get());
	}

	/**
	 * Revoke a token by adding it to the blacklist.
	 *
	 * @param token The token to revoke
	 * @return true if the token was successfully revoked
	 */
	public boolean revokeToken(String token) {
		try {
			String cleanToken = token.startsWith("Bearer ") ? token.substring(7).trim() : token.trim();
			SignedJWT signedJWT = SignedJWT.parse(cleanToken);
			JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

			String jti = claims.getJWTID();
			if (jti == null) {
				log.warn("Cannot revoke token without jti claim");
				return false;
			}

			Date expiration = claims.getExpirationTime();
			Instant expiresAt = expiration != null ? expiration.toInstant() : clock.instant().plus(this.expiration);

			tokenBlacklist.put(jti, expiresAt);
			log.info("Revoked token: jti={}", jti);

			// Cleanup expired entries periodically
			cleanupBlacklist();

			return true;
		} catch (ParseException e) {
			log.error("Failed to parse token for revocation", e);
			return false;
		}
	}

	/**
	 * Revoke a token by its JTI (JWT ID).
	 */
	public void revokeTokenById(String jti, Instant expiresAt) {
		if (jti != null) {
			tokenBlacklist.put(jti, expiresAt != null ? expiresAt : clock.instant().plus(expiration));
			log.info("Revoked token by ID: jti={}", jti);
		}
	}

	/**
	 * Check if a token is blacklisted.
	 */
	public boolean isTokenBlacklisted(String jti) {
		Instant expiry = tokenBlacklist.get(jti);
		if (expiry == null) {
			return false;
		}
		// Remove from blacklist if expired
		if (clock.instant().isAfter(expiry)) {
			tokenBlacklist.remove(jti);
			return false;
		}
		return true;
	}

	/**
	 * Get the configured token expiration duration.
	 */
	public Duration getExpiration() {
		return expiration;
	}

	// Private helper methods

	private JWTClaims extractClaims(JWTClaimsSet claims) {
		UUID userId = parseUuid(claims.getClaim(CLAIM_USER_ID));
		UUID clientId = parseUuid(claims.getClaim(CLAIM_CLIENT_ID));

		String clientTypeStr = (String) claims.getClaim(CLAIM_CLIENT_TYPE);
		ClientType clientType = ClientType.fromString(clientTypeStr).orElse(ClientType.PUBLIC);

		@SuppressWarnings("unchecked")
		Set<String> roles = claims.getClaim(CLAIM_ROLES) instanceof java.util.Collection<?>c
				? Set.copyOf((java.util.Collection<String>) c)
				: Set.of();

		@SuppressWarnings("unchecked")
		Set<String> permissions = claims.getClaim(CLAIM_PERMISSIONS) instanceof java.util.Collection<?>c
				? Set.copyOf((java.util.Collection<String>) c)
				: Set.of();

		Instant issuedAt = claims.getIssueTime() != null ? claims.getIssueTime().toInstant() : null;
		Instant expiresAt = claims.getExpirationTime() != null ? claims.getExpirationTime().toInstant() : null;

		// Collect additional claims (excluding standard ones)
		Set<String> standardClaims = Set.of("jti", "iss", "aud", "sub", "iat", "nbf", "exp", CLAIM_USER_ID,
				CLAIM_CLIENT_ID, CLAIM_CLIENT_TYPE, CLAIM_ROLES, CLAIM_PERMISSIONS);

		Map<String, Object> additionalClaims = new java.util.HashMap<>();
		claims.getClaims().forEach((key, value) -> {
			if (!standardClaims.contains(key)) {
				additionalClaims.put(key, value);
			}
		});

		return new JWTClaims(claims.getJWTID(), userId, clientId, clientType, roles, permissions, issuedAt, expiresAt,
				Map.copyOf(additionalClaims));
	}

	private UUID parseUuid(Object value) {
		if (value == null) {
			return null;
		}
		try {
			return value instanceof UUID u ? u : UUID.fromString(value.toString());
		} catch (IllegalArgumentException e) {
			log.debug("Failed to parse UUID from: {}", value);
			return null;
		}
	}

	private void cleanupBlacklist() {
		Instant now = clock.instant();
		tokenBlacklist.entrySet().removeIf(entry -> now.isAfter(entry.getValue()));
	}

	private static byte[] getOrGenerateSecret(Config config) {
		if (config.hasPath(CONFIG_SECRET_KEY)) {
			String secret = config.getString(CONFIG_SECRET_KEY);
			if (secret.length() >= 32) {
				return secret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
			}
			log.warn("Configured secret key is too short, generating random secret");
		}

		log.warn("No secret key configured, generating random secret (not suitable for production clusters)");
		byte[] secret = new byte[32];
		new SecureRandom().nextBytes(secret);
		return secret;
	}

	private static KeyPair generateRsaKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048, new SecureRandom());
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("RSA algorithm not available", e);
		}
	}

	private static JWSAlgorithm parseAlgorithm(String algorithmName) {
		return switch (algorithmName.toUpperCase()) {
		case "HS256" -> JWSAlgorithm.HS256;
		case "HS384" -> JWSAlgorithm.HS384;
		case "HS512" -> JWSAlgorithm.HS512;
		case "RS256" -> JWSAlgorithm.RS256;
		case "RS384" -> JWSAlgorithm.RS384;
		case "RS512" -> JWSAlgorithm.RS512;
		default -> {
			log.warn("Unknown algorithm {}, falling back to HS256", algorithmName);
			yield JWSAlgorithm.HS256;
		}
		};
	}

	private static boolean isHmacAlgorithm(JWSAlgorithm algorithm) {
		return algorithm == JWSAlgorithm.HS256 || algorithm == JWSAlgorithm.HS384 || algorithm == JWSAlgorithm.HS512;
	}

	private static boolean isRsaAlgorithm(JWSAlgorithm algorithm) {
		return algorithm == JWSAlgorithm.RS256 || algorithm == JWSAlgorithm.RS384 || algorithm == JWSAlgorithm.RS512;
	}

	private static String getConfigString(Config config, String path, String defaultValue) {
		return config.hasPath(path) ? config.getString(path) : defaultValue;
	}

	private static Duration getConfigDuration(Config config, String path, Duration defaultValue) {
		return config.hasPath(path) ? config.getDuration(path) : defaultValue;
	}
}