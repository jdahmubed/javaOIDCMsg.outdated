package com.auth0.jwt;

import static com.auth0.jwt.GoogleJwtCreatorTest.generateRandomExpDateInFuture;
import static com.auth0.jwt.GoogleJwtCreatorTest.generateRandomIatDateInPast;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import static java.util.Arrays.asList;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Arrays;
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
        JWT verifier = verification.createVerifierForGoogle("picture", "email", asList("accounts.fake.com"), asList("audience"),
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
        JWT verifier = verification.createVerifierForGoogle("picture", "email",asList("accounts.fake.com"), asList("audience"),
                exp, iat, "name").build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testConfigurableToMultipleKeys() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String[] arr = {"accounts.fake.com", "subject"};
        String token = GoogleJwtCreator.build()
                .withPicture("picture")
                .withEmail("email")
                .withSubject("subject", "subject2")
                .withAudience("audience", "audience2")
                .withExp(exp)
                .withIat(iat)
                .withName("name")
                .withIssuer("issuer", "issuer2")
                .sign(algorithm);
        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle("picture", "email", asList("issuer", "issuer2"), asList("audience", "audience2"),
                new Date(2017,12,1), iat, "name").build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testConfigurableToIncorrectNumberMultipleKeysForAudience() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'aud' value doesn't contain the required audience.");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String[] arr = {"accounts.fake.com", "subject"};
        String token = GoogleJwtCreator.build()
                .withPicture("picture")
                .withEmail("email")
                .withSubject("subject", "subject2")
                .withAudience("audience", "audience2")
                .withExp(exp)
                .withIat(iat)
                .withName("name")
                .withIssuer("issuer", "issuer2")
                .sign(algorithm);
        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle("picture", "email", asList("issuer", "issuer2"), asList("audience"),
                new Date(2017,12,1), iat, "name").build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testConfigurableToIncorrectValueMultipleKeysForAudience() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'aud' value doesn't contain the required audience.");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String[] arr = {"accounts.fake.com", "subject"};
        String token = GoogleJwtCreator.build()
                .withPicture("picture")
                .withEmail("email")
                .withSubject("subject", "subject2")
                .withAudience("audience", "audience2")
                .withExp(exp)
                .withIat(iat)
                .withName("name")
                .withIssuer("issuer", "issuer2")
                .sign(algorithm);
        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle("picture", "email", asList("issuer", "issuer2"), asList("audience", "audience3"),
                new Date(2017,12,1), iat, "name").build();
        DecodedJWT jwt = verifier.decode(token);
    }
}