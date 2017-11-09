package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertTrue;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.*;

public class ScopedJwtCreatorTest {

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
        String token = ScopedJwtCreator.build()
                .withScope("scope")
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped("scope", asList("accounts.fake.com"), asList("audience")).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testGoogleJwtCreatorScopeNotProvided() throws Exception {
        thrown.expect(Exception.class);
        thrown.expectMessage("Standard claim: Scope has not been set");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ScopedJwtCreator.build()
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped("scope", asList("accounts.fake.com"), asList("audience")).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
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

    protected static void verifyClaims(Map<String,Claim> claims, Date exp) {
        assertTrue(claims.get(PublicClaims.ISSUER).asList(String.class).get(0).equals("accounts.fake.com"));
        assertTrue(claims.get(PublicClaims.SUBJECT).asList(String.class).get(0).equals("subject"));
        assertTrue(claims.get(PublicClaims.AUDIENCE).asString().equals("audience"));
        assertTrue(claims.get(PublicClaims.EXPIRES_AT).asDate().toString().equals(exp.toString()));
    }
}