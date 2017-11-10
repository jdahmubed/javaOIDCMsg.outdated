package com.auth0.jwt;

import static com.auth0.jwt.GoogleJwtCreatorTest.*;
import static com.auth0.jwt.TimeUtil.generateRandomExpDateInFuture;
import static com.auth0.jwt.TimeUtil.generateRandomIatDateInPast;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.GoogleVerification;
import static java.util.Arrays.asList;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Date;
import java.util.Map;

public class ExtendedJwtCreatorTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private static final Date exp = generateRandomExpDateInFuture();
    private static final Date iat = generateRandomIatDateInPast();
    private static final Date nbf = iat;

    @Test
    public void testExtendedJwtCreatorAllStandardClaimsMustBeRequired() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)  //this must be called first since ExtendedJwtCreator.build() returns an instance of ExtendedJwtCreator
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .sign(algorithm);
        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, new Date(1477592000)).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testExtendedJwtCreatorNbfNotProvided() throws Exception {
        thrown.expect(Exception.class);
        thrown.expectMessage("Standard claim: Nbf has not been set");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .sign(algorithm);
        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, new Date(1477592000)).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testExtendedJwtCreatorNoneAlgorithmNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
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

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, new Date(1477592000)).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testExtendedJwtCreatorNoneAlgorithmNotSpecifiedButStillNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
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

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, new Date(1477592000)).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testExtendedJwtCreatorNoneAlgorithmAllowed() throws Exception {
        Algorithm algorithm = Algorithm.none();
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
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

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, new Date(1477592000)).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimStringValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
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

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, new Date(1477592000)).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimIntegerValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .withNonStandardClaim("nonStandardClaim", 999)
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, new Date(1477592000)).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimLongValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .withNonStandardClaim("nonStandardClaim", 999L)
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, new Date(1477592000)).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimDoubleValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .withNonStandardClaim("nonStandardClaim", 9.99)
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, new Date(1477592000)).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimBooleanValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .withNonStandardClaim("nonStandardClaim", true)
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, new Date(1477592000)).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimDateValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .withNonStandardClaim("nonStandardClaim", new Date())
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, new Date(1477592000)).build();
        DecodedJWT jwt = verifier.decode(token);
    }
}
