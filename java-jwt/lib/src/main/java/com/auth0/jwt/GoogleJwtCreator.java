package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;

import java.util.Date;
import java.util.HashMap;

public class GoogleJwtCreator extends JWTCreator.Builder{

    private JWTCreator.Builder jwt;
    private HashMap<String, Boolean> addedClaims;

    public GoogleJwtCreator() {
        jwt = JWT.create();
        addedClaims = new HashMap<String, Boolean>()
        {{
            put("Name", false);
            put("Email", false);
            put("Picture", false);
            put("Issuer", false);
            put("Subject", false);
            put("Audience", false);
            put("Iat", false);
            put("Exp", false);
        }};
    }

    /**
     * Add a name
     */
    public GoogleJwtCreator withName(String name) {
        jwt.withNonStandardClaim("name", name);
        addedClaims.put("Name", true);
        return this;
    }

    /**
     * Add an email
     */
    public GoogleJwtCreator withEmail(String email) {
        jwt.withNonStandardClaim("email", email);
        addedClaims.put("Email", true);
        return this;
    }

    /**
     * Add a picture
     */
    public GoogleJwtCreator withPicture(String picture) {
        jwt.withNonStandardClaim("picture", picture);
        addedClaims.put("Picture", true);
        return this;
    }

    /**
     * Add an issuer
     */
    public GoogleJwtCreator withIssuer(String... issuer) {
        jwt.withIssuer(issuer);
        addedClaims.put("Issuer", true);
        return this;
    }

    /**
     * Add a subject
     */
    public GoogleJwtCreator withSubject(String... subject) {
        jwt.withSubject(subject);
        addedClaims.put("Subject", true);
        return this;
    }

    /**
     * Add an audience
     */
    public GoogleJwtCreator withAudience(String... audience) {
        jwt.withAudience(audience);
        addedClaims.put("Audience", true);
        return this;
    }

    /**
     * Add an iat
     */
    public GoogleJwtCreator withIat(Date iat) {
        jwt.withIssuedAt(iat);
        addedClaims.put("Iat", true);
        return this;
    }

    /**
     * Add an exp
     */
    public GoogleJwtCreator withExp(Date exp) {
        jwt.withExpiresAt(exp);
        addedClaims.put("Exp", true);
        return this;
    }

    /**
     * Developer specifies whether they want the None algo to be allowed or not
     */
    public GoogleJwtCreator setIsNoneAlgorithmAllowed(boolean isNoneAlgorithmAllowed) {
        jwt.setIsNoneAlgorithmAllowed(isNoneAlgorithmAllowed);
        return this;
    }

    /**
     * Add an algorithm
     * @param algorithm
     */
    public String sign(Algorithm algorithm) throws Exception {
        if(!jwt.getIsNoneAlgorithmAllowed() && algorithm.equals(Algorithm.none())) {
            throw new IllegalAccessException("None algorithm isn't allowed");
        }
        String JWS = jwt.sign(algorithm);
        verifyClaims();
        return JWS;
    }

    private void verifyClaims() throws Exception {
        for(String claim : addedClaims.keySet())
            if(!addedClaims.get(claim))
                throw new Exception("Standard claim: " + claim + " has not been set");
    }

    public static GoogleJwtCreator build() {
        return new GoogleJwtCreator();
    }
}
