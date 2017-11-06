package com.auth0.jwt.interfaces;

import com.auth0.jwt.JWT;

import java.util.Date;

public interface Verification {
    Verification withIssuer(String issuer);

    Verification withSubject(String subject);

    Verification withAudience(String... audience);

    Verification acceptLeeway(long leeway) throws IllegalArgumentException;

    Verification acceptExpiresAt(long leeway) throws IllegalArgumentException;

    Verification acceptNotBefore(long leeway) throws IllegalArgumentException;

    Verification acceptIssuedAt(long leeway) throws IllegalArgumentException;

    Verification withJWTId(String jwtId);

    Verification withNonStandardClaim(String name, Boolean value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, Integer value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, Long value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, Double value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, String value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, Date value) throws IllegalArgumentException;

    Verification withArrayClaim(String name, String... items) throws IllegalArgumentException;

    Verification withArrayClaim(String name, Integer... items) throws IllegalArgumentException;

    Verification createVerifier(String issuer, String subject, String audience) throws IllegalArgumentException;

    JWT build();
}
