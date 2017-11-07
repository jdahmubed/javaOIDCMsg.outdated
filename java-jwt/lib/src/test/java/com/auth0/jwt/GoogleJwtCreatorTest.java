package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import org.mockito.Mockito;

import java.util.Date;
import java.util.HashMap;

public class GoogleJwtCreatorTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testGoogleJwtCreatorAllStandardClaimsMustBeRequired() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withPicture("picture")
                .withEmail("email")
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(new Date(2017,12,1))
                .withIat(new Date(1477592000))
                .withName("name")
                .sign(algorithm);
        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifier("accounts.fake.com", "subject", "audience").build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorWhenCertainRequiredClaimIsntProvided() throws Exception {
        thrown.expect(Exception.class);
        thrown.expectMessage("Standard claim: Picture has not been set");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withEmail("email")
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(new Date(2017,12,1))
                .withIat(new Date(1477592000))
                .withName("name")
                .sign(algorithm);

        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifier("accounts.fake.com", "subject", "audience").build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNoneAlgorithmNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = GoogleJwtCreator.build()
                .withPicture("picture")
                .withEmail("email")
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(new Date(2017,12,1))
                .withIat(new Date(1477592000))
                .withName("name")
                .setIsNoneAlgorithmAllowed(false)
                .sign(algorithm);

        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifier("accounts.fake.com", "subject", "audience").build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNoneAlgorithmNotSpecifiedButStillNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = GoogleJwtCreator.build()
                .withPicture("picture")
                .withEmail("email")
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(new Date(2017,12,1))
                .withIat(new Date(1477592000))
                .withName("name")
                .sign(algorithm);

        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifier("accounts.fake.com", "subject", "audience").build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNoneAlgorithmAllowed() throws Exception {
        Algorithm algorithm = Algorithm.none();
        String token = GoogleJwtCreator.build()
                .withPicture("picture")
                .withEmail("email")
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(new Date(2017,12,1))
                .withIat(new Date(1477592000))
                .withName("name")
                .setIsNoneAlgorithmAllowed(true)
                .sign(algorithm);

        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifier("accounts.fake.com", "subject", "audience").build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorInvalidIssuer() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'iss' value doesn't match the required one.");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withPicture("picture")
                .withEmail("email")
                .withIssuer("invalid")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(new Date(2017,12,1))
                .withIat(new Date(1477592000))
                .withName("name")
                .sign(algorithm);

        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifier("accounts.fake.com", "subject", "audience").build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorInvalidSubject() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'sub' value doesn't match the required one.");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withPicture("picture")
                .withEmail("email")
                .withIssuer("accounts.fake.com")
                .withSubject("invalid")
                .withAudience("audience")
                .withExp(new Date(2017,12,1))
                .withIat(new Date(1477592000))
                .withName("name")
                .sign(algorithm);

        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifier("accounts.fake.com", "subject", "audience").build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorInvalidAudience() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'aud' value doesn't contain the required audience.");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withPicture("picture")
                .withEmail("email")
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("invalid")
                .withExp(new Date(2017,12,1))
                .withIat(new Date(1477592000))
                .withName("name")
                .sign(algorithm);

        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifier("accounts.fake.com", "subject", "audience").build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNonStandardClaim() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withPicture("picture")
                .withEmail("email")
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(new Date(2017,12,1))
                .withIat(new Date(1477592000))
                .withName("name")
                .withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue")
                .sign(algorithm);
        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifier("accounts.fake.com", "subject", "audience").build();
        DecodedJWT jwt = verifier.decode(token);
    }
}