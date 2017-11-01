package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class MainTestSignatures {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testComplainOnNone() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("The Algorithm cannot be null.");
        String token = JWT.create().withIssuer("accounts.fake.com").withSubject("subject")
                .withAudience("audience")
                .sign(null);
        Algorithm algorithmFake = Algorithm.HMAC256("secret");
        JWTVerifier verifier = JWT.require(algorithmFake)
                .withIssuer("accounts.fake.com")
                .build();
        DecodedJWT jwt = verifier.verify(token);
    }

    @Test
    public void testValidatesStandardClaims() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = JWT.create().withIssuer("accounts.fake.com").withSubject("subject")
                .withAudience("audience")
                .sign(algorithm);
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("accounts.fake.com").withSubject("subject")
                .withAudience("audience")
                .build();
        DecodedJWT jwt = verifier.verify(token);
    }

    @Test
    public void testDoesntValidateByDefault_CanSkipVerify() throws Exception {
        //this test will pass if you don't call verify
        //not calling verify defeats the purpose
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = JWT.create().withIssuer("accounts.fake.com").withSubject("subject")
                .withAudience("audience")
                .sign(algorithm);
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("accounts.fake.com").withSubject("subject")
                .withAudience("audience")
                .build();
    }

    @Test
    public void testNonStandardClaims() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'claim' value doesn't match the required one.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = JWT.create()
                .withClaim("claim", "blah")
                .sign(algorithm);
        JWTVerifier verifier = JWT.require(algorithm)
                .withClaim("claim", "blahWrong")
                .build();
        DecodedJWT jwt = verifier.verify(token);
    }
}