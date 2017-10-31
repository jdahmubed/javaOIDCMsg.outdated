import com.auth0.jwt.JWT;
import com.sun.org.apache.xml.internal.security.signature.InvalidSignatureValueException;
import exceptions.*;
import org.json.JSONObject;
import org.omg.CORBA.DynAnyPackage.InvalidValue;

import java.security.InvalidKeyException;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Message extends MutableMapping {

    public Message(Map<String,Object> args) {
        throw new UnsupportedOperationException();
    }

    public String toUrlEncoded(int lev) throws MissingRequiredAttribute, InvalidKeyException,
            InvalidValue, TypeError, Exception, UnicodeEncodeError {
        throw new UnsupportedOperationException();
    }

    public Message fromUrlEncoded(String urlencoded) throws InvalidKeyException, InvalidValue,
            ParameterError, TooManyValues {
        throw new UnsupportedOperationException();
    }

    public Map<String, Object> toMap(int lev) throws InvalidKeyException, InvalidValue {
        throw new UnsupportedOperationException();
    }

    public Message fromMap(Map<Object, String> map) throws InvalidKeyException, InvalidValue {
        throw new UnsupportedOperationException();
    }

    /**
     * @param: _deser this is a NoneType in Python, which I believe
     *         could translate to an Object type in Java
     */
    private void addValue(String skey, String vtyp, String key, String val, Object _deser, boolean isNullAllowed)
            throws Exception, DecodeError, InvalidValue, IllegalArgumentException, TooManyValues {
        throw new UnsupportedOperationException();
    }

    /**
     * @param: indent this is a NoneType in Python, which I believe
     *         could translate to an Object type in Java
     */
    public JSONObject toJson(int lev, Object indent) {
        throw new UnsupportedOperationException();
    }

    public Message fromJson(JSONObject txt) {
        throw new UnsupportedOperationException();
    }

    public JWT toJwt(List key, String algorithm, int lev) {
        throw new UnsupportedOperationException();
    }

    private void addKey(KeyJar keyJar, Object issuer, Object key, String keyType, String kid, Object noKidIssuer)
        throws KeyError {
        throw new UnsupportedOperationException();
    }

    public List<Object> getVerifyKeys(KeyJar keyJar, Set key, Map<String,Object> jso, Map<String,String> header, JWT jwt, Map<String,Object> args)
        throws KeyError {
        throw new UnsupportedOperationException();
    }

    public Message fromJwt(JWT txt, List key, boolean shouldVerify, KeyJar keyjar, Map<String,Object> args)
        throws AssertionError, InvalidAlgorithmException, InvalidSignatureValueException, InvalidKeyException, Exception {
        throw new UnsupportedOperationException();
    }

    public String toString() {
        throw new UnsupportedOperationException();
    }

    private Object typeCheck(Object type, Set allowed, Object val, boolean na) throws NotAllowedValue {
        throw new UnsupportedOperationException();
    }

    public boolean verify(Map<String,Object> args) throws KeyError, MissingRequiredAttribute, InvalidValue, NotAllowedValue{
        throw new UnsupportedOperationException();
    }

    public List<Object> getKeys() {
        throw new UnsupportedOperationException();
    }

    public Object getItem(String item) {
        throw new UnsupportedOperationException();
    }

    public Object get(String item, Object defaultValue) throws KeyError {
        throw new UnsupportedOperationException();
    }

    /**
     *
     * @return List<Map<String, Object>> This is because the return value could be a list of
     *                                  maps of a string to a string, int, or list of strings.
     */
    public List<Map<String, Object>> getItems() {
        throw new UnsupportedOperationException();
    }

    public List<Object> getValues() {
        throw new UnsupportedOperationException();
    }

    public boolean contains(Object item) {
        throw new UnsupportedOperationException();
    }

    public String request(String location, boolean fragment_enc) {
        throw new UnsupportedOperationException();
    }

    public void setItem(Object key, Object value) throws KeyError {
        throw new UnsupportedOperationException();
    }

    public boolean equals(Object other) {
        throw new UnsupportedOperationException();
    }

    public void deleteItem(String key) {
        throw new UnsupportedOperationException();
    }

    public int getLength() {
        throw new UnsupportedOperationException();
    }

    public Map<String, Object> extra() {
        throw new UnsupportedOperationException();
    }

    public boolean onlyExtras() {
        throw new UnsupportedOperationException();
    }

    public void update(Object item) throws InvalidValue {
        throw new UnsupportedOperationException();
    }

    public JWE toJwe(Map<String,Object> keys, ContentEncryptionAlgorithm enc, KeyManagementAlgorithm alg, int lev) {
        throw new UnsupportedOperationException();
    }

    public Message fromJwe(JWE msg, Map<String,Object> keys) {
        throw new UnsupportedOperationException();
    }

    public void weed() {
        throw new UnsupportedOperationException();
    }

    public void removeBlanks() {
        throw new UnsupportedOperationException();
    }
}
