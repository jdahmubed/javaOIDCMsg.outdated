package com.auth0.jwt.interfaces;

import java.util.Date;
import java.util.List;

public interface GoogleVerification extends Verification{

    Verification createVerifierForGoogle(String picture, String email, List<String> issuer,
                                         List<String> audience, Date exp, Date iat, String name);

    Verification withPicture(String picture);

    Verification withEmail(String email);

    GoogleVerification withName(String name);
}
