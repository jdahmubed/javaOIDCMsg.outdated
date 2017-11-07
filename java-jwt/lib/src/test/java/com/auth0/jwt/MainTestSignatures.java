package com.auth0.jwt;

import static com.auth0.jwt.GoogleJwtCreatorTest.generateRandomExpDateInFuture;
import static com.auth0.jwt.GoogleJwtCreatorTest.generateRandomIatDateInPast;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Date;

public class MainTestSignatures {

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private Date exp = generateRandomExpDateInFuture();
    private Date iat = generateRandomIatDateInPast();

    @Test
    public void testComplainOnNone() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("The Algorithm cannot be null.");

        String token = JWT.create().withIssuer("accounts.fake.com").withSubject("subject")
                .withAudience("audience")
                .sign(null);
        Verification verification = JWT.require(null);
        JWT verifier = verification.createVerifierForGoogle("picture", "email","accounts.fake.com", "audience",
                exp, iat, "name").build();
        DecodedJWT jwt = verifier.decode(token);
    }
    @Test
    public void testVerifyingWithEmptyKey() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Empty key");
        Algorithm algorithm = Algorithm.HMAC256("");
        String token = GoogleJwtCreator.build()
                .withPicture("picture")
                .withEmail("email")
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName("name")
                .withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue")
                .sign(algorithm);
        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle("picture", "email","accounts.fake.com", "audience",
                exp, iat, "name").build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Ignore("doesn't work atm")
    @Test
    public void testConfigurableToMultipleKeys() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String[] arr = {"issuer1", "issuer2"};
        String token = GoogleJwtCreator.build()
                .withPicture("picture")
                .withEmail("email")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName("name")
                //.withIssuer("issuer")
                .withArrayClaim(PublicClaims.ISSUER, arr)
                .sign(algorithm);
        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle("picture", "email","accounts.fake.com", "audience",
                new Date(2017,12,1), iat, "name").build();
        DecodedJWT jwt = verifier.decode(token);
    }

    /*@Test
    public void testConfigurableToMultipleKeys() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'issuer' value doesn't match the required one.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String[] arr = {"iss1", "iss2", "iss3"};
        String token = JWT.create().withArrayClaim("issuer", arr).withSubject("subject")
                .withAudience("audience")
                .sign(algorithm);
        String[] arr2 = {"iss1", "iss2", "iss4"};
        JWT verifier = JWT.require(algorithm)
                .withArrayClaim("issuer", arr2)
                .build();
        //DecodedJWT jwt = verifier.verify(token);
    }*/
}