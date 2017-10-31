import com.auth0.jwt.interfaces.Payload;
import exceptions.KeyError;
import exceptions.NoSuitableSigningKeys;

import java.security.Key;
import java.util.Map;

public class JWT {

    public JWT(KeyJar keyJar, String iss, String signAlg, JasonWebToken msgType,
               boolean shouldEncrypt, String encEnc, String encAlg) {
        throw new UnsupportedOperationException();
    }

    private String encrypt(Payload payload, String cty) {
        throw new UnsupportedOperationException();
    }

    public Map<String, Object> packInit() {
        throw new UnsupportedOperationException();
    }

    public Key packKey(String owner, String kid) throws NoSuitableSigningKeys {
        throw new UnsupportedOperationException();
    }

    public String pack(String kid, String owner, Object clsInstance, Map<String,Object> args) throws KeyError{
        throw new UnsupportedOperationException();
    }

    private Map<String,Object> verify(JWS rj, String token) {
        throw new UnsupportedOperationException();
    }

    private byte[] decrypt(JWE rj, String token) throws KeyError{
        throw new UnsupportedOperationException();
    }

    public Object unpack(String token) throws KeyError, Exception{
        throw new UnsupportedOperationException();
    }

}
