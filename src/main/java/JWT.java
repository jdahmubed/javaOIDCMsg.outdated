import com.auth0.jwt.interfaces.Payload;
import exceptions.KeyError;
import exceptions.NoSuitableSigningKeys;

import java.util.HashMap;

public class JWT {

    public JWT(KeyJar keyJar, String iss, String signAlg, JasonWebToken msgType,
               boolean shouldEncrypt, String encEnc, String encAlg) {
        throw new UnsupportedOperationException();
    }

    private String encrypt(Payload payload, String cty) {
        throw new UnsupportedOperationException();
    }

    public HashMap<String, Object> packInit() {
        throw new UnsupportedOperationException();
    }

    public Object packKey(String owner, String kid) throws NoSuitableSigningKeys {
        throw new UnsupportedOperationException();
    }

    public String pack(String kid, String owner, Object clsInstance, HashMap<String,Object> args) throws KeyError{
        throw new UnsupportedOperationException();
    }

    private Object verify(Object rj, Object token) {
        throw new UnsupportedOperationException();
    }

    private Object decrypt(Object rj, Object token) throws KeyError{
        throw new UnsupportedOperationException();
    }

    public Object unpack(Object token) throws KeyError, Exception{
        throw new UnsupportedOperationException();
    }

}
