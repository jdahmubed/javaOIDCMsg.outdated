package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.auth0.jwt.verification.VerificationAndAssertion;

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
        VerificationAndAssertion.verifyAlgorithm(jwt, algorithm);
        algorithm.verify(jwt);
        VerificationAndAssertion.verifyClaims(clock, jwt, claims);
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
        protected final Algorithm algorithm;
        protected final Map<String, Object> claims;
        private long defaultLeeway;

        BaseVerification(Algorithm algorithm) throws IllegalArgumentException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }

            this.algorithm = algorithm;
            this.claims = new HashMap<>();
            this.defaultLeeway = 0;
        }

        @Override
        public Verification withNbf(long nbf) {
            throw new UnsupportedOperationException("you shouldn't be calling this method");
        }

        @Override
        public Verification createVerifierForScoped(String scope, List<String> issuer, List<String> audience, long expLeeway, long iatLeeway) {
            throw new UnsupportedOperationException("you shouldn't be calling this method");
        }

        @Override
        public Verification createVerifierForImplicit(List<String> issuer, List<String> audience, long iatLeeway) {
            throw new UnsupportedOperationException("you shouldn't be calling this method");
        }

        @Override
        public Verification createVerifierForFb(String userId, String appId) {
            throw new UnsupportedOperationException("you shouldn't be calling this method");
        }

        @Override
        public Verification withUserId(String userId) {
            throw new UnsupportedOperationException("you shouldn't be calling this method");
        }

        @Override
        public Verification withAppId(String appId) {
            throw new UnsupportedOperationException("you shouldn't be calling this method");
        }

        /**
         * Require a specific Issuer ("iss") claim.
         * Allows for multiple issuers
         *
         * @param issuer the required Issuer value
         * @return this same Verification instance.
         */
        @Override
        public Verification withIssuer(String... issuer) {
            requireClaim(PublicClaims.ISSUER, Arrays.asList(issuer));
            return this;
        }

        /**
         * Require a specific Subject ("sub") claim.
         * Allows for multiple subjects
         *
         * @param subject the required Subject value
         * @return this same Verification instance.
         */
        @Override
        public Verification withSubject(String... subject) {
            requireClaim(PublicClaims.SUBJECT, Arrays.asList(subject));
            return this;
        }

        /**
         * Require a specific Audience ("aud") claim.
         * Allows for multiple audience
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
            VerificationAndAssertion.assertPositive(leeway);
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
            VerificationAndAssertion.assertPositive(leeway);
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
            VerificationAndAssertion.assertPositive(leeway);
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
            VerificationAndAssertion.assertPositive(leeway);
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
            VerificationAndAssertion.assertNonNull(name);
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
            VerificationAndAssertion.assertNonNull(name);
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
            VerificationAndAssertion.assertNonNull(name);
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
            VerificationAndAssertion.assertNonNull(name);
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
            VerificationAndAssertion.assertNonNull(name);
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
            VerificationAndAssertion.assertNonNull(name);
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
            VerificationAndAssertion.assertNonNull(name);
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
            VerificationAndAssertion.assertNonNull(name);
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

        protected void addLeewayToDateClaims() {
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

        protected void requireClaim(String name, Object value) {
            if (value == null) {
                claims.remove(name);
                return;
            }
            claims.put(name, value);
        }
    }
}
