package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.impl.PublicClaims;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class GoogleJwtCreator extends JWTCreator.Builder{

    private JWTCreator.Builder jwt;
    private HashMap<String, Boolean> addedClaims = new HashMap<String, Boolean>()
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

    /**
     * Add a name
     */
    public JWTCreator.Builder addName(String name) {
        assertNonNull(name);
        jwt.withClaim("name", name);
        addedClaims.put("Name", true);
        return this;
    }

    /**
     * Add an email
     */
    public JWTCreator.Builder addEmail(String email) {
        assertNonNull(email);
        jwt.withClaim("email", email);
        addedClaims.put("Email", true);
        return this;
    }

    /**
     * Add a picture
     */
    public JWTCreator.Builder addPicture(String picture) {
        assertNonNull(picture);
        jwt.withClaim("picture", picture);
        addedClaims.put("Picture", true);
        return this;
    }

    /**
     * Add an issuer
     */
    public JWTCreator.Builder addIssuer(String issuer) {
        assertNonNull(issuer);
        jwt.withIssuer(issuer);
        addedClaims.put("Issuer", true);
        return this;
    }

    /**
     * Add a subject
     */
    public JWTCreator.Builder addSubject(String subject) {
        assertNonNull(subject);
        jwt.withSubject(subject);
        addedClaims.put("Subject", true);
        return this;
    }

    /**
     * Add an audience
     */
    public JWTCreator.Builder addAudience(String audience) {
        assertNonNull(audience);
        jwt.withAudience(audience);
        addedClaims.put("Audience", true);
        return this;
    }

    /**
     * Add an iat
     */
    public JWTCreator.Builder addIat(Date iat) {
        jwt.withIssuedAt(iat);
        addedClaims.put("Iat", true);
        return this;
    }

    /**
     * Add an exp
     */
    public JWTCreator.Builder addExp(Date exp) {
        jwt.withExpiresAt(exp);
        addedClaims.put("Exp", true);
        return this;
    }

    /**
     * Add an algorithm
     * @param algorithm
     */
    public String sign(Algorithm algorithm, JWTVerifier jwtVerifier) {
        String JWS = jwt.sign(algorithm);
        try {
            verifyClaims();
        } catch (Exception e) {
            e.printStackTrace();
        }
        jwtVerifier.verify(JWS);
        return JWS;
    }

    private void verifyClaims() throws Exception {
        for(String claim : addedClaims.keySet())
            if(!addedClaims.get(claim))
                throw new Exception("Standard claim: " + claim + " has not been set");
    }

}
