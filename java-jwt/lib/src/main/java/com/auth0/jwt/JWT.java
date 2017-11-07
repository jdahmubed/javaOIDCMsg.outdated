package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

import java.util.*;

@SuppressWarnings("WeakerAccess")
public class JWT {

    private final Algorithm algorithm;
    final Map<String, Object> claims;
    private final Clock clock;

    JWT(Algorithm algorithm, Map<String, Object> claims, Clock clock) {
        this.algorithm = algorithm;
        this.claims = Collections.unmodifiableMap(claims);
        this.clock = clock;
    }

    /**
     * Convert the given token to a DecodedJWT
     * <p>
     * Note that this method <b>doesn't verify the token's signature!</b> Use it only if you trust the token or you already verified it.
     *
     * @param token with jwt format as string.
     * @return a decoded JWT.
     * @throws AlgorithmMismatchException     if the algorithm stated in the token's header it's not equal to the one defined in the {@link JWT}.
     * @throws SignatureVerificationException if the signature is invalid.
     * @throws TokenExpiredException          if the token has expired.
     * @throws InvalidClaimException          if a claim contained a different value than the expected one.
     */
    public DecodedJWT decode(String token) throws JWTDecodeException {
        DecodedJWT jwt = new JWTDecoder(token);
        verifyAlgorithm(jwt, algorithm);
        algorithm.verify(jwt);
        verifyClaims(jwt, claims);
        return jwt;
    }

    /**
     * Returns a {Verification} to be used to validate token signature.
     *
     * @param algorithm that will be used to verify the token's signature.
     * @return Verification
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    public static Verification require(Algorithm algorithm) {
        return JWT.init(algorithm);
    }

    /**
     * Returns a Json Web Token builder used to create and sign tokens
     *
     * @return a token builder.
     */
    public static JWTCreator.Builder create() {
        return JWTCreator.init();
    }



    //----------------this is from JWTVerifier--------


    /**
     * Initialize a Verification instance using the given Algorithm.
     *
     * @param algorithm the Algorithm to use on the JWT verification.
     * @return a JWT.BaseVerification instance to configure.
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    static Verification init(Algorithm algorithm) throws IllegalArgumentException {
        return new JWT.BaseVerification(algorithm);
    }

    /**
     * The Verification class holds the Claims required by a JWT to be valid.
     */
    public static class BaseVerification implements Verification {
        private final Algorithm algorithm;
        private final Map<String, Object> claims;
        private long defaultLeeway;

        BaseVerification(Algorithm algorithm) throws IllegalArgumentException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }

            this.algorithm = algorithm;
            this.claims = new HashMap<>();
            this.defaultLeeway = 0;
        }

        /**
         * Create Verification object
         * @param issuer
         * @param subject
         * @param audience
         * @return
         */
        public Verification createVerifier(String issuer, String subject, String audience) {
            return withIssuer(issuer).withSubject(subject).withAudience(audience);
        }

        /**
         * Require a specific Issuer ("iss") claim.
         *
         * @param issuer the required Issuer value
         * @return this same Verification instance.
         */
        @Override
        public Verification withIssuer(String issuer) {
            requireClaim(PublicClaims.ISSUER, issuer);
            return this;
        }

        /**
         * Require a specific Subject ("sub") claim.
         *
         * @param subject the required Subject value
         * @return this same Verification instance.
         */
        @Override
        public Verification withSubject(String subject) {
            requireClaim(PublicClaims.SUBJECT, subject);
            return this;
        }

        /**
         * Require a specific Audience ("aud") claim.
         *
         * @param audience the required Audience value
         * @return this same Verification instance.
         */
        @Override
        public Verification withAudience(String... audience) {
            requireClaim(PublicClaims.AUDIENCE, Arrays.asList(audience));
            return this;
        }

        /**
         * Define the default window in seconds in which the Not Before, Issued At and Expires At Claims will still be valid.
         * Setting a specific leeway value on a given Claim will override this value for that Claim.
         *
         * @param leeway the window in seconds in which the Not Before, Issued At and Expires At Claims will still be valid.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if leeway is negative.
         */
        @Override
        public Verification acceptLeeway(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            this.defaultLeeway = leeway;
            return this;
        }

        /**
         * Set a specific leeway window in seconds in which the Expires At ("exp") Claim will still be valid.
         * Expiration Date is always verified when the value is present. This method overrides the value set with acceptLeeway
         *
         * @param leeway the window in seconds in which the Expires At Claim will still be valid.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if leeway is negative.
         */
        @Override
        public Verification acceptExpiresAt(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            requireClaim(PublicClaims.EXPIRES_AT, leeway);
            return this;
        }

        /**
         * Set a specific leeway window in seconds in which the Not Before ("nbf") Claim will still be valid.
         * Not Before Date is always verified when the value is present. This method overrides the value set with acceptLeeway
         *
         * @param leeway the window in seconds in which the Not Before Claim will still be valid.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if leeway is negative.
         */
        @Override
        public Verification acceptNotBefore(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            requireClaim(PublicClaims.NOT_BEFORE, leeway);
            return this;
        }

        /**
         * Set a specific leeway window in seconds in which the Issued At ("iat") Claim will still be valid.
         * Issued At Date is always verified when the value is present. This method overrides the value set with acceptLeeway
         *
         * @param leeway the window in seconds in which the Issued At Claim will still be valid.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if leeway is negative.
         */
        @Override
        public Verification acceptIssuedAt(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            requireClaim(PublicClaims.ISSUED_AT, leeway);
            return this;
        }

        /**
         * Require a specific JWT Id ("jti") claim.
         *
         * @param jwtId the required Id value
         * @return this same Verification instance.
         */
        @Override
        public Verification withJWTId(String jwtId) {
            requireClaim(PublicClaims.JWT_ID, jwtId);
            return this;
        }

        /**
         * Require a specific Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Override
        public Verification withNonStandardClaim(String name, Boolean value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        /**
         * Require a specific Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Override
        public Verification withNonStandardClaim(String name, Integer value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        /**
         * Require a specific Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Override
        public Verification withNonStandardClaim(String name, Long value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        /**
         * Require a specific Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Override
        public Verification withNonStandardClaim(String name, Double value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        /**
         * Require a specific Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Override
        public Verification withNonStandardClaim(String name, String value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        /**
         * Require a specific Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Override
        public Verification withNonStandardClaim(String name, Date value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        /**
         * Require a specific Array Claim to contain at least the given items.
         *
         * @param name  the Claim's name.
         * @param items the items the Claim must contain.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Override
        public Verification withArrayClaim(String name, String... items) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, items);
            return this;
        }

        /**
         * Require a specific Array Claim to contain at least the given items.
         *
         * @param name  the Claim's name.
         * @param items the items the Claim must contain.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Override
        public Verification withArrayClaim(String name, Integer... items) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, items);
            return this;
        }

        /**
         * Creates a new and reusable instance of the JWT with the configuration already provided.
         *
         * @return a new JWT instance.
         */
        @Override
        public JWT build() {
            return this.build(new ClockImpl());
        }

        /**
         * Creates a new and reusable instance of the JWT the configuration already provided.
         * ONLY FOR TEST PURPOSES.
         *
         * @param clock the instance that will handle the current time.
         * @return a new JWT instance with a custom Clock.
         */
        public JWT build(Clock clock) {
            addLeewayToDateClaims();
            return new JWT(algorithm, claims, clock);
        }

        private void assertPositive(long leeway) {
            if (leeway < 0) {
                throw new IllegalArgumentException("Leeway value can't be negative.");
            }
        }

        private void assertNonNull(String name) {
            if (name == null) {
                throw new IllegalArgumentException("The Custom Claim's name can't be null.");
            }
        }

        private void addLeewayToDateClaims() {
            if (!claims.containsKey(PublicClaims.EXPIRES_AT)) {
                claims.put(PublicClaims.EXPIRES_AT, defaultLeeway);
            }
            if (!claims.containsKey(PublicClaims.NOT_BEFORE)) {
                claims.put(PublicClaims.NOT_BEFORE, defaultLeeway);
            }
            if (!claims.containsKey(PublicClaims.ISSUED_AT)) {
                claims.put(PublicClaims.ISSUED_AT, defaultLeeway);
            }
        }

        private void requireClaim(String name, Object value) {
            if (value == null) {
                claims.remove(name);
                return;
            }
            claims.put(name, value);
        }
    }

    private void verifyAlgorithm(DecodedJWT jwt, Algorithm expectedAlgorithm) throws AlgorithmMismatchException {
        if (!expectedAlgorithm.getName().equals(jwt.getAlgorithm())) {
            throw new AlgorithmMismatchException("The provided Algorithm doesn't match the one defined in the JWT's Header.");
        }
    }

    private void verifyClaims(DecodedJWT jwt, Map<String, Object> claims) throws TokenExpiredException, InvalidClaimException {
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            switch (entry.getKey()) {
                case PublicClaims.AUDIENCE:
                    //noinspection unchecked
                    assertValidAudienceClaim(jwt.getAudience(), (List<String>) entry.getValue());
                    break;
                case PublicClaims.EXPIRES_AT:
                    assertValidDateClaim(jwt.getExpiresAt(), (Long) entry.getValue(), true);
                    break;
                case PublicClaims.ISSUED_AT:
                    assertValidDateClaim(jwt.getIssuedAt(), (Long) entry.getValue(), false);
                    break;
                case PublicClaims.NOT_BEFORE:
                    assertValidDateClaim(jwt.getNotBefore(), (Long) entry.getValue(), false);
                    break;
                case PublicClaims.ISSUER:
                    assertValidStringClaim(entry.getKey(), jwt.getIssuer(), (String) entry.getValue());
                    break;
                case PublicClaims.JWT_ID:
                    assertValidStringClaim(entry.getKey(), jwt.getId(), (String) entry.getValue());
                    break;
                case PublicClaims.SUBJECT:
                    assertValidStringClaim(entry.getKey(), jwt.getSubject(), (String) entry.getValue());
                    break;
                default:
                    assertValidClaim(jwt.getClaim(entry.getKey()), entry.getKey(), entry.getValue());
                    break;
            }
        }
    }

    private void assertValidClaim(Claim claim, String claimName, Object value) {
        boolean isValid = false;
        if (value instanceof String) {
            isValid = value.equals(claim.asString());
        } else if (value instanceof Integer) {
            isValid = value.equals(claim.asInt());
        } else if (value instanceof Long) {
            isValid = value.equals(claim.asLong());
        } else if (value instanceof Boolean) {
            isValid = value.equals(claim.asBoolean());
        } else if (value instanceof Double) {
            isValid = value.equals(claim.asDouble());
        } else if (value instanceof Date) {
            isValid = value.equals(claim.asDate());
        } else if (value instanceof Object[]) {
            List<Object> claimArr = Arrays.asList(claim.as(Object[].class));
            List<Object> valueArr = Arrays.asList((Object[]) value);
            isValid = claimArr.containsAll(valueArr);
        }

        if (!isValid) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }

    private void assertValidStringClaim(String claimName, String value, String expectedValue) {
        if (!expectedValue.equals(value)) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }

    private void assertValidDateClaim(Date date, long leeway, boolean shouldBeFuture) {
        Date today = clock.getToday();
        today.setTime((long) Math.floor((today.getTime() / 1000) * 1000)); // truncate millis
        if (shouldBeFuture) {
            assertDateIsFuture(date, leeway, today);
        } else {
            assertDateIsPast(date, leeway, today);
        }
    }

    private void assertDateIsFuture(Date date, long leeway, Date today) {
        today.setTime(today.getTime() - leeway * 1000);
        if (date != null && today.after(date)) {
            throw new TokenExpiredException(String.format("The Token has expired on %s.", date));
        }
    }

    private void assertDateIsPast(Date date, long leeway, Date today) {
        today.setTime(today.getTime() + leeway * 1000);
        if (date != null && today.before(date)) {
            throw new InvalidClaimException(String.format("The Token can't be used before %s.", date));
        }
    }

    private void assertValidAudienceClaim(List<String> audience, List<String> value) {
        if (audience == null || !audience.containsAll(value)) {
            throw new InvalidClaimException("The Claim 'aud' value doesn't contain the required audience.");
        }
    }
}
