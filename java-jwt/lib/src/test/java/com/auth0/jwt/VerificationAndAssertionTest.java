package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.auth0.jwt.verification.VerificationAndAssertion;
import static java.util.Arrays.asList;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class VerificationAndAssertionTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testAssertPositiveWithNegativeNumber() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Leeway value can't be negative.");

        VerificationAndAssertion.assertPositive(-1);
    }

    @Test
    public void testAssertNullWithNullString() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("The Custom Claim's name can't be null.");

        VerificationAndAssertion.assertNonNull(null);
    }

    @Test
    public void testVerifyAlgorithmWithMismatchingAlgorithms() throws Exception {
        thrown.expect(AlgorithmMismatchException.class);
        thrown.expectMessage("The provided Algorithm doesn't match the one defined in the JWT's Header.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(Algorithm.none());
        JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

}
