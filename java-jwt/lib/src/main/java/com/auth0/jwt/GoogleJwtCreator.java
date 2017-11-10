package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.impl.PublicClaims;

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 * The GoogleJwtCreator class holds the sign method to generate a complete Google JWT (with Signature) from a given Header and Payload content.
 */
public class GoogleJwtCreator {

    protected JWTCreator.Builder jwt;
    protected HashMap<String, Boolean> addedClaims;
    protected Set<String> publicClaims;

    public GoogleJwtCreator() {
        jwt = JWT.create();
        addedClaims = new HashMap<String, Boolean>() {{
            put("Name", false);
            put("Email", false);
            put("Picture", false);
            put("Issuer", false);
            put("Subject", false);
            put("Audience", false);
            put("Iat", false);
            put("Exp", false);
        }};
        publicClaims = new HashSet<String>() {{
            add(PublicClaims.ISSUER);
            add(PublicClaims.SUBJECT);
            add(PublicClaims.EXPIRES_AT);
            add(PublicClaims.NOT_BEFORE);
            add(PublicClaims.ISSUED_AT);
            add(PublicClaims.JWT_ID);
            add(PublicClaims.AUDIENCE);
        }};
    }


    /**
     * Add a specific Name ("name") claim to the Payload.
     *
     * @param name the Name value.
     * @return this same Builder instance.
     */
    protected GoogleJwtCreator withName(String name) {
        jwt.withNonStandardClaim("name", name);
        addedClaims.put("Name", true);
        return this;
    }

    /**
     * Add a specific Email ("email") claim to the Payload.
     *
     * @param email the Email value.
     * @return this same Builder instance.
     */
    GoogleJwtCreator withEmail(String email) {
        jwt.withNonStandardClaim("email", email);
        addedClaims.put("Email", true);
        return this;
    }

    /**
     * Add a specific Picture ("picture") claim to the Payload.
     *
     * @param picture the Picture value.
     * @return this same Builder instance.
     */
    protected GoogleJwtCreator withPicture(String picture) {
        jwt.withNonStandardClaim("picture", picture);
        addedClaims.put("Picture", true);
        return this;
    }

    /**
     * Add a specific Issuer ("issuer") claim to the Payload.
     * Allows for multiple issuers
     *
     * @param issuer the Issuer value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withIssuer(String... issuer) {
        jwt.withIssuer(issuer);
        addedClaims.put("Issuer", true);
        return this;
    }

    /**
     * Add a specific Subject ("subject") claim to the Payload.
     * Allows for multiple subjects
     *
     * @param subject the Subject value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withSubject(String... subject) {
        jwt.withSubject(subject);
        addedClaims.put("Subject", true);
        return this;
    }

    /**
     * Add a specific Audience ("audience") claim to the Payload.
     * Allows for multiple audience
     *
     * @param audience the Audience value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withAudience(String... audience) {
        jwt.withAudience(audience);
        addedClaims.put("Audience", true);
        return this;
    }

    /**
     * Add a specific Issued At ("iat") claim to the Payload.
     *
     * @param iat the Issued At value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withIat(Date iat) {
        jwt.withIssuedAt(iat);
        addedClaims.put("Iat", true);
        return this;
    }

    /**
     * Add a specific Expires At ("exp") claim to the Payload.
     *
     * @param exp the Expires At value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withExp(Date exp) {
        jwt.withExpiresAt(exp);
        addedClaims.put("Exp", true);
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
    public GoogleJwtCreator withNonStandardClaim(String name, String value) {
        jwt.withNonStandardClaim(name, value);
        return this;
    }

    /**
     * Add a custom Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Builder instance.
     * @throws IllegalArgumentException if the name is null.
     */
    public GoogleJwtCreator withNonStandardClaim(String name, Boolean value) throws IllegalArgumentException {
        jwt.withNonStandardClaim(name, value);
        return this;
    }

    /**
     * Add a custom Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Builder instance.
     * @throws IllegalArgumentException if the name is null.
     */
    public GoogleJwtCreator withNonStandardClaim(String name, Integer value) throws IllegalArgumentException {
        jwt.withNonStandardClaim(name, value);
        return this;
    }

    /**
     * Add a custom Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Builder instance.
     * @throws IllegalArgumentException if the name is null.
     */
    public GoogleJwtCreator withNonStandardClaim(String name, Long value) throws IllegalArgumentException {
        jwt.withNonStandardClaim(name, value);
        return this;
    }

    /**
     * Add a custom Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Builder instance.
     * @throws IllegalArgumentException if the name is null.
     */
    public GoogleJwtCreator withNonStandardClaim(String name, Double value) throws IllegalArgumentException {
        jwt.withNonStandardClaim(name, value);
        return this;
    }

    /**
     * Add a custom Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Builder instance.
     * @throws IllegalArgumentException if the name is null.
     */
    public GoogleJwtCreator withNonStandardClaim(String name, Date value) throws IllegalArgumentException {
        jwt.withNonStandardClaim(name, value);
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
    public GoogleJwtCreator withArrayClaim(String name, String... items) throws IllegalArgumentException {
        jwt.withArrayClaim(name, items);
        if(publicClaims.contains(name))
            addedClaims.put(name, true);
        return this;
    }

    /**
     * Developer explicitly specifies whether they want to accept
     * NONE algorithms or not.
     *
     * @param isNoneAlgorithmAllowed
     * @return
     */
    public GoogleJwtCreator setIsNoneAlgorithmAllowed(boolean isNoneAlgorithmAllowed) {
        jwt.setIsNoneAlgorithmAllowed(isNoneAlgorithmAllowed);
        return this;
    }

    /**
     * Creates a new JWT and signs it with the given algorithm.
     *
     * @param algorithm used to sign the JWT
     * @return a new JWT token
     * @throws IllegalAccessException   if the developer didn't want NONE algorithm to be allowed and it was passed in
     * @throws IllegalArgumentException if the provided algorithm is null.
     * @throws JWTCreationException     if the claims could not be converted to a valid JSON or there was a problem with the signing key.
     */
    public String sign(Algorithm algorithm) throws Exception {
        if(!jwt.getIsNoneAlgorithmAllowed() && algorithm.equals(Algorithm.none())) {
            throw new IllegalAccessException("None algorithm isn't allowed");
        }
        String JWS = jwt.sign(algorithm);
        verifyClaims();
        return JWS;
    }

    /**
     * Verifies that all the standard claims were provided
     * @throws Exception if all the standard claims weren't provided
     */
    private void verifyClaims() throws Exception {
        for(String claim : addedClaims.keySet())
            if(!addedClaims.get(claim))
                throw new Exception("Standard claim: " + claim + " has not been set");
    }

    public static GoogleJwtCreator build() {
        return new GoogleJwtCreator();
    }
}
