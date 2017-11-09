package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.GoogleVerification;
import com.auth0.jwt.interfaces.Verification;

import java.util.Date;
import java.util.List;

public class ScopedJWT extends JWT.BaseVerification implements Verification{

    ScopedJWT(Algorithm algorithm) throws IllegalArgumentException {
        super(algorithm);
    }

    /**
     * Create Verification object for verification purposes
     * @issuer scope
     * @param issuer
     * @param audience
     * @return
     */
    public Verification createVerifierForScoped(String scope, List<String> issuer,
                                                List<String> audience) {
        return withScope(scope).withIssuer(issuer.toArray(new String[issuer.size()])).withAudience(audience.toArray(new String[audience.size()]));
    }

    /**
     * Require a specific Scope ("scope") claim.
     *
     * @param scope the required Scope value
     * @return this same Verification instance.
     */
    public Verification withScope(String scope) {
        requireClaim("scope", scope);
        return this;
    }

    public static Verification require(Algorithm algorithm) {
        return ScopedJWT.init(algorithm);
    }

    static Verification init(Algorithm algorithm) throws IllegalArgumentException {
        return new ScopedJWT(algorithm);
    }

    @Override
    public Verification withNbf(Date nbf) {
        throw new UnsupportedOperationException("you shouldn't be calling this method");
    }

    @Override
    public JWT build() {
        return this.build(new ClockImpl());
    }

    public JWT build(Clock clock) {
        addLeewayToDateClaims();
        return new JWT(algorithm, claims, clock);
    }
}
