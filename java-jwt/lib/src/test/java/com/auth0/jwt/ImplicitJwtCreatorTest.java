package com.auth0.jwt;

import static com.auth0.jwt.TimeUtil.generateRandomIatDateInPast;
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

public class ImplicitJwtCreatorTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private static final Date iat = generateRandomIatDateInPast();


    @Test
    public void testGoogleJwtCreatorAllStandardClaimsMustBeRequired() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience")).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testGoogleJwtCreatorIssuerNotProvided() throws Exception {
        thrown.expect(Exception.class);
        thrown.expectMessage("Standard claim: Issuer has not been set");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withSubject("subject")
                .withAudience("audience")
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience")).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testGoogleJwtCreatorNoneAlgorithmNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = ImplicitJwtCreator.build()
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .setIsNoneAlgorithmAllowed(false)
                .withIat(iat)
                .sign(algorithm);

        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience")).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNoneAlgorithmNotSpecifiedButStillNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = ImplicitJwtCreator.build()
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience")).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNoneAlgorithmAllowed() throws Exception {
        Algorithm algorithm = Algorithm.none();
        String token = ImplicitJwtCreator.build()
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .setIsNoneAlgorithmAllowed(true)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience")).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimStringValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue")
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience")).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimIntegerValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .withNonStandardClaim("nonStandardClaim", 999)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience")).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimLongValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .withNonStandardClaim("nonStandardClaim", 999L)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience")).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimDoubleValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .withNonStandardClaim("nonStandardClaim", 9.99)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience")).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimBooleanValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .withNonStandardClaim("nonStandardClaim", true)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience")).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimDateValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .withNonStandardClaim("nonStandardClaim", new Date())
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience")).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    private static void verifyClaims(Map<String,Claim> claims) {
        assertTrue(claims.get(PublicClaims.ISSUER).asList(String.class).get(0).equals("accounts.fake.com"));
        assertTrue(claims.get(PublicClaims.SUBJECT).asList(String.class).get(0).equals("subject"));
        assertTrue(claims.get(PublicClaims.AUDIENCE).asString().equals("audience"));
    }
}