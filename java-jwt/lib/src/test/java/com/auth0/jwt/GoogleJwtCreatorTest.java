package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

import java.util.Date;

public class GoogleJwtCreatorTest {

    @Test
    public void testGoogleJwtCreator() throws Exception {
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
}
