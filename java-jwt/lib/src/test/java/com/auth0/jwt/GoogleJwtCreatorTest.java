package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertTrue;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.junit.Assert.assertThat;

import java.text.SimpleDateFormat;
import java.util.*;

public class GoogleJwtCreatorTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private static final Date exp = generateRandomExpDateInFuture();
    private static final Date iat = generateRandomIatDateInPast();
    public static final String PICTURE = "picture";
    public static final String EMAIL = "email";
    public static final String NAME = "name";

    @Test
    public void testGoogleJwtCreatorAllStandardClaimsMustBeRequired() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .sign(algorithm);
        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                exp, iat, NAME).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testGoogleJwtCreatorWhenCertainRequiredClaimIsntProvided() throws Exception {
        thrown.expect(Exception.class);
        thrown.expectMessage("Standard claim: Picture has not been set");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .sign(algorithm);

        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(PICTURE, EMAIL,asList("accounts.fake.com"), asList("audience"),
                exp, iat, NAME).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNoneAlgorithmNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = GoogleJwtCreator.build()
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .setIsNoneAlgorithmAllowed(false)
                .sign(algorithm);

        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(PICTURE, EMAIL,asList("accounts.fake.com"), asList("audience"),
                exp, iat, NAME).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNoneAlgorithmNotSpecifiedButStillNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = GoogleJwtCreator.build()
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .sign(algorithm);

        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(PICTURE, EMAIL,asList("accounts.fake.com"), asList("audience"),
                exp, iat, NAME).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNoneAlgorithmAllowed() throws Exception {
        Algorithm algorithm = Algorithm.none();
        String token = GoogleJwtCreator.build()
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .setIsNoneAlgorithmAllowed(true)
                .sign(algorithm);

        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(PICTURE, EMAIL,asList("accounts.fake.com"), asList("audience"),
                exp, iat, NAME).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testGoogleJwtCreatorInvalidIssuer() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'iss' value doesn't match the required one.");

        Algorithm algorithm = Algorithm.none();
        String token = GoogleJwtCreator.build()
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("invalid")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .setIsNoneAlgorithmAllowed(true)
                .withName(NAME)
                .sign(algorithm);

        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(PICTURE, EMAIL,asList("accounts.fake.com"), asList("audience"),
                exp, iat, NAME).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorInvalidAudience() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'aud' value doesn't contain the required audience.");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("invalid")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .sign(algorithm);

        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(PICTURE, EMAIL,asList("accounts.fake.com"), asList("audience"),
                exp, iat, NAME).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNonStandardClaim() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue")
                .sign(algorithm);
        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(PICTURE, EMAIL,asList("accounts.fake.com"), asList("audience"),
                exp, iat, NAME).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorExpTimeHasPassed() throws Exception {
        thrown.expect(TokenExpiredException.class);
        thrown.expectMessage("The Token has expired on Wed Oct 29 00:00:00 PDT 2014.");

        String myDate = "2014/10/29";
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");
        Date date = sdf.parse(myDate);
        long exp = date.getTime();
        Date expDate = new Date(exp);

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(expDate)
                .withIat(iat)
                .withName(NAME)
                .sign(algorithm);
        Verification verification = JWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(PICTURE, EMAIL,asList("accounts.fake.com"), asList("audience"),
                expDate, iat, NAME).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    public static Date generateRandomExpDateInFuture() {
        Random rnd = new Random();
        return new Date(Math.abs(System.currentTimeMillis() + rnd.nextLong()));
    }

    public static Date generateRandomIatDateInPast() {
        GregorianCalendar gc = new GregorianCalendar();
        int year = randBetween(1900, 2010);
        gc.set(gc.YEAR, year);
        int dayOfYear = randBetween(1, gc.getActualMaximum(gc.DAY_OF_YEAR));
        gc.set(gc.DAY_OF_YEAR, dayOfYear);

        return new Date(gc.getTimeInMillis());
    }

    public static int randBetween(int start, int end) {
        return start + (int)Math.round(Math.random() * (end - start));
    }

    private static void verifyClaims(Map<String,Claim> claims) {
        assertTrue(claims.get(PICTURE).asString().equals(PICTURE));
        assertTrue(claims.get(EMAIL).asString().equals(EMAIL));
        assertTrue(claims.get(PublicClaims.ISSUER).asList(String.class).get(0).equals("accounts.fake.com"));
        assertTrue(claims.get(PublicClaims.SUBJECT).asList(String.class).get(0).equals("subject"));
        assertTrue(claims.get(PublicClaims.AUDIENCE).asString().equals("audience"));
        assertTrue(claims.get(PublicClaims.EXPIRES_AT).asDate().toString().equals(exp.toString()));
        assertTrue(claims.get(NAME).asString().equals(NAME));
    }
}