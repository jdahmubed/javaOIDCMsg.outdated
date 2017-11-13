package com.auth0.jwt;

import static com.auth0.jwt.TimeUtil.generateRandomExpDateInFuture;
import static com.auth0.jwt.TimeUtil.generateRandomIatDateInPast;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.GoogleVerification;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertTrue;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Date;
import java.util.List;
import java.util.Map;

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
        GoogleVerification verification = GoogleJWT.require(null);
        JWT verifier = verification.createVerifierForGoogle(GoogleJwtCreatorTest.PICTURE, GoogleJwtCreatorTest.EMAIL, asList("accounts.fake.com"), asList("audience"),
                 GoogleJwtCreatorTest.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testVerifyingWithEmptyKey() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Empty key");
        Algorithm algorithm = Algorithm.HMAC256("");
        String token = GoogleJwtCreator.build()
                .withPicture(GoogleJwtCreatorTest.PICTURE)
                .withEmail(GoogleJwtCreatorTest.EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(GoogleJwtCreatorTest.NAME)
                .withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue")
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(GoogleJwtCreatorTest.PICTURE, GoogleJwtCreatorTest.EMAIL,asList("accounts.fake.com"), asList("audience"),
                 GoogleJwtCreatorTest.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testConfigurableToMultipleKeys() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withPicture(GoogleJwtCreatorTest.PICTURE)
                .withEmail(GoogleJwtCreatorTest.EMAIL)
                .withSubject("subject", "subject2")
                .withAudience("audience", "audience2")
                .withExp(exp)
                .withIat(iat)
                .withName(GoogleJwtCreatorTest.NAME)
                .withIssuer("issuer", "issuer2")
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(GoogleJwtCreatorTest.PICTURE, GoogleJwtCreatorTest.EMAIL, asList("issuer", "issuer2"), asList("audience", "audience2"),
                GoogleJwtCreatorTest.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String,Claim> claims = jwt.getClaims();
        assertTrue(claims.get(GoogleJwtCreatorTest.PICTURE).asString().equals(GoogleJwtCreatorTest.PICTURE));
        assertTrue(claims.get(GoogleJwtCreatorTest.EMAIL).asString().equals(GoogleJwtCreatorTest.EMAIL));
        List<String> issuers = claims.get(PublicClaims.ISSUER).asList(String.class);
        assertTrue(issuers.get(0).equals("issuer"));
        assertTrue(issuers.get(1).equals("issuer2"));
        List<String> subjects = claims.get(PublicClaims.SUBJECT).asList(String.class);
        assertTrue(subjects.get(0).equals("subject"));
        assertTrue(subjects.get(1).equals("subject2"));
        List<String> audience = claims.get(PublicClaims.AUDIENCE).asList(String.class);
        assertTrue(audience.get(0).equals("audience"));
        assertTrue(audience.get(1).equals("audience2"));
        assertTrue(claims.get(PublicClaims.EXPIRES_AT).asDate().toString().equals(exp.toString()));
        assertTrue(claims.get(GoogleJwtCreatorTest.NAME).asString().equals(GoogleJwtCreatorTest.NAME));
    }

    @Test
    public void testConfigurableToIncorrectNumberMultipleKeysForAudience() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'aud' value doesn't contain the required audience.");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String[] arr = {"accounts.fake.com", "subject"};
        String token = GoogleJwtCreator.build()
                .withPicture(GoogleJwtCreatorTest.PICTURE)
                .withEmail(GoogleJwtCreatorTest.EMAIL)
                .withSubject("subject", "subject2")
                .withAudience("audience", "audience2")
                .withExp(exp)
                .withIat(iat)
                .withName(GoogleJwtCreatorTest.NAME)
                .withIssuer("issuer", "issuer2")
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(GoogleJwtCreatorTest.PICTURE, GoogleJwtCreatorTest.EMAIL, asList("issuer", "issuer2"), asList("audience"),
                GoogleJwtCreatorTest.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testConfigurableToIncorrectValueMultipleKeysForAudience() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'aud' value doesn't contain the required audience.");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String[] arr = {"accounts.fake.com", "subject"};
        String token = GoogleJwtCreator.build()
                .withPicture(GoogleJwtCreatorTest.PICTURE)
                .withEmail(GoogleJwtCreatorTest.EMAIL)
                .withSubject("subject", "subject2")
                .withAudience("audience", "audience2")
                .withExp(exp)
                .withIat(iat)
                .withName(GoogleJwtCreatorTest.NAME)
                .withIssuer("issuer", "issuer2")
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(GoogleJwtCreatorTest.PICTURE, GoogleJwtCreatorTest.EMAIL, asList("issuer", "issuer2"), asList("audience", "audience3"),
                GoogleJwtCreatorTest.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }
}