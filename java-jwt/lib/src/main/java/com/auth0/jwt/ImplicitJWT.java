package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.Verification;

import java.util.List;

public class ImplicitJWT extends JWT.BaseVerification implements Verification{

    ImplicitJWT(Algorithm algorithm) throws IllegalArgumentException {
        super(algorithm);
    }

    /**
     * Create Verification object for verification purposes
     * @issuer scope
     * @param issuer
     * @param audience
     * @return
     */
    public Verification createVerifierForImplicit(List<String> issuer,
                                                List<String> audience) {
        return withIssuer(issuer.toArray(new String[issuer.size()])).withAudience(audience.toArray(new String[audience.size()]));
    }

    public static Verification require(Algorithm algorithm) {
        return ImplicitJWT.init(algorithm);
    }

    static Verification init(Algorithm algorithm) throws IllegalArgumentException {
        return new ImplicitJWT(algorithm);
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
