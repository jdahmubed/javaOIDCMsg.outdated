import com.auth0.jwt.JWT;
import com.sun.org.apache.xml.internal.security.signature.InvalidSignatureValueException;
import exceptions.*;
import org.json.JSONObject;
import org.omg.CORBA.DynAnyPackage.InvalidValue;

import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

public class Message extends MutableMapping {

    public Message(HashMap<String,Object> args) {
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

    public HashMap<String, Object> toDictionary(int lev) throws InvalidKeyException, InvalidValue {
        throw new UnsupportedOperationException();
    }

    public Message fromDictionary(HashMap<Object, String> dictionary) throws InvalidKeyException, InvalidValue {
        throw new UnsupportedOperationException();
    }

    private void addValue(Object skey, Object vtyp, Object key, Object val, Object _deser, boolean isNullAllowed)
            throws Exception, DecodeError, InvalidValue, IllegalArgumentException, TooManyValues {
        throw new UnsupportedOperationException();
    }

    public JSONObject toJson(int lev, Object indent) {
        throw new UnsupportedOperationException();
    }

    public Message fromJson(JSONObject txt) {
        throw new UnsupportedOperationException();
    }

    public JWT toJwt(Object key, String algorithm, int lev) {
        throw new UnsupportedOperationException();
    }

    private void addKey(HashMap<String,String> keyJar, Object issuer, Object key, String keyType, String kid, Object noKidIssuer)
        throws KeyError {
        throw new UnsupportedOperationException();
    }

    public ArrayList<Object> getVerifyKeys(KeyJar keyJar, Set key, HashMap<String,Object> jso, HashMap<String,String> header, JWT jwt, HashMap<String,Object> args)
        throws KeyError {
        throw new UnsupportedOperationException();
    }

    public Message fromJwt(JWT txt, Object key, boolean verify, KeyJar keyjar, HashMap<String,Object> args)
        throws AssertionError, InvalidAlgorithmException, InvalidSignatureValueException, InvalidKeyException, Exception {
        throw new UnsupportedOperationException();
    }

    public String toString() {
        throw new UnsupportedOperationException();
    }

    private Object typeCheck(Object type, Set allowed, Object val, boolean na) throws NotAllowedValue {
        throw new UnsupportedOperationException();
    }

    public boolean verify(HashMap<String,Object> args) throws KeyError, MissingRequiredAttribute, InvalidValue, NotAllowedValue{
        throw new UnsupportedOperationException();
    }

    public ArrayList<Object> getKeys() {
        throw new UnsupportedOperationException();
    }

    public Object getItem(String item) {
        throw new UnsupportedOperationException();
    }

    public Object get(String item, Object defaultValue) throws KeyError {
        throw new UnsupportedOperationException();
    }

    public ArrayList<HashMap<Object, Object>> getItems() {
        throw new UnsupportedOperationException();
    }

    public ArrayList<Object> getValues() {
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

    public void deleteItem(Object key) {
        throw new UnsupportedOperationException();
    }

    public int getLength() {
        throw new UnsupportedOperationException();
    }

    public HashMap<String, Object> extra() {
        throw new UnsupportedOperationException();
    }

    public boolean onlyExtras() {
        throw new UnsupportedOperationException();
    }

    public void update(Object item) throws InvalidValue {
        throw new UnsupportedOperationException();
    }

    public JWE toJwe(HashMap<String,Object> keys, ContentEncryptionAlgorithm enc, KeyManagementAlgorithm alg, int lev) {
        throw new UnsupportedOperationException();
    }

    public Message fromJwe(JWE msg, HashMap<String,Object> keys) {
        throw new UnsupportedOperationException();
    }

    public void weed() {
        throw new UnsupportedOperationException();
    }

    public void removeBlanks() {
        throw new UnsupportedOperationException();
    }
}
