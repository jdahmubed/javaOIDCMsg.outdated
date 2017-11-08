package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.GoogleVerification;
import com.auth0.jwt.interfaces.Verification;

import java.util.Date;
import java.util.List;
import java.util.Map;

public class GoogleJWT extends JWT.BaseVerification implements GoogleVerification{

    GoogleJWT(Algorithm algorithm) throws IllegalArgumentException {
        super(algorithm);
    }

    /**
     * Create Verification object for verification purposes
     * @param picture
     * @param email
     * @param issuer
     * @param audience
     * @param exp
     * @param iat
     * @param name
     * @return
     */
    public Verification createVerifierForGoogle(String picture, String email, List<String> issuer,
                                                List<String> audience, Date exp, Date iat, String name) {
        return withPicture(picture).withName(name).withEmail(email).withIssuer(issuer.toArray(new String[issuer.size()])).withAudience(audience.toArray(new String[audience.size()]));
    }

    /**
     * Require a specific Picture ("picture") claim.
     *
     * @param picture the required Picture value
     * @return this same Verification instance.
     */
    @Override
    public GoogleVerification withPicture(String picture) {
        requireClaim("picture", picture);
        return this;
    }

    /**
     * Require a specific Email ("email") claim.
     *
     * @param email the required Email value
     * @return this same Verification instance.
     */
    @Override
    public Verification withEmail(String email) {
        requireClaim("email", email);
        return this;
    }

    /**
     * Require a specific Name ("name") claim.
     *
     * @param name the required Name value
     * @return this same Verification instance.
     */
    @Override
    public GoogleVerification withName(String name) {
        requireClaim("name", name);
        return this;
    }

    public static GoogleVerification require(Algorithm algorithm) {
        return GoogleJWT.init(algorithm);
    }

    static GoogleVerification init(Algorithm algorithm) throws IllegalArgumentException {
        return new GoogleJWT(algorithm);
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
