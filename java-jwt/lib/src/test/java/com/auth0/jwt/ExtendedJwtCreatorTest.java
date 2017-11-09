package com.auth0.jwt;

import static com.auth0.jwt.GoogleJwtCreatorTest.*;
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
}
