import exceptions.KeyError;
import exceptions.KeyIOError;
import exceptions.MessageException;
import org.omg.CORBA.DynAnyPackage.InvalidValue;

import java.security.Key;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

public class KeyJar {

    private HashMap<String,Object> issuerKeys;
    private boolean verifySSL;
    private long removeAfter;

    public KeyJar(HashMap<String,Object> issuerKeys, boolean verifySSL, long removeAfter) {
        this.issuerKeys = issuerKeys;
        this.verifySSL = verifySSL;
        this.removeAfter = removeAfter;
    }

    public String repr() {
        throw new UnsupportedOperationException();
    }

    public KeyBundle add(String issuer, String url, HashMap<String,Object> args) throws KeyError{
        throw new UnsupportedOperationException();
    }

    public void addSymmetric(String issuer, Object key, ArrayList usage) {
        throw new UnsupportedOperationException();
    }

    public void addKb(String issuer, Object kb) throws KeyError{
        throw new UnsupportedOperationException();
    }

    public void setItem(String issuer, Object val) {
        throw new UnsupportedOperationException();
    }

    public Set items() {
        throw new UnsupportedOperationException();
    }

    public ArrayList get(Key keyUse, KeyType keyType, String issuer, String kid, HashMap<String,Object> args)
        throws KeyError, AssertionError{
        throw new UnsupportedOperationException();
    }

    public ArrayList getSigningKey(KeyType keyType, String owner, String kid, HashMap<String,Object> args) {
        throw new UnsupportedOperationException();
    }

    public ArrayList getVerifyKey(KeyType keyType, String owner, String kid, HashMap<String,Object> args) {
        throw new UnsupportedOperationException();
    }

    public ArrayList getEncryptKey(KeyType keyType, String owner, String kid, HashMap<String,Object> args) {
        throw new UnsupportedOperationException();
    }

    public ArrayList getDecryptKey(KeyType keyType, String owner, String kid, HashMap<String,Object> args) {
        throw new UnsupportedOperationException();
    }

    public Key getKeyByKid(String kid, String owner) {
        throw new UnsupportedOperationException();
    }

    public boolean contains(Object item) {
        throw new UnsupportedOperationException();
    }

    public ArrayList xKeys(String var, Object part) {
        throw new UnsupportedOperationException();
    }

    public ArrayList verifyKeys(Object part) {
        throw new UnsupportedOperationException();
    }

    public ArrayList decryptKeys(Object part) {
        throw new UnsupportedOperationException();
    }

    public Object getItem(String issuer) throws KeyError{
        throw new UnsupportedOperationException();
    }

    public void removeKey(String issuer, KeyType keyType, Key key) throws KeyError {
        throw new UnsupportedOperationException();
    }

    public void update(Object kj) throws KeyError{
        throw new UnsupportedOperationException();
    }

    public Object matchOwner(String url) throws KeyIOError {
        throw new UnsupportedOperationException();
    }

    public String toString() {
        throw new UnsupportedOperationException();
    }

    public ArrayList getKeys() {
        throw new UnsupportedOperationException();
    }

    public HashMap<String,Object> loadKeys(String pcr, String issuer, boolean replace)
        throws MessageException, KeyError
    {
        throw new UnsupportedOperationException();
    }

    public Object find(String source, String issuer) throws KeyError {
        throw new UnsupportedOperationException();
    }

    public ArrayList dumpIssuerKeys(String issuer) throws KeyError {
        throw new UnsupportedOperationException();
    }

    public HashMap<String,Object> exportJwks(boolean isPrivate, String issuer) {
        throw new UnsupportedOperationException();
    }

    public void importJwks(HashMap<String,Object> jwks, String issuer) throws KeyError, InvalidValue {
        throw new UnsupportedOperationException();
    }

    public void addKeyJar(KeyJar keyJar) throws KeyError {
        throw new UnsupportedOperationException();
    }

    public HashMap<String, Object> dump() {
        throw new UnsupportedOperationException();
    }

    public void restore(HashMap<String,Object> info) {
        throw new UnsupportedOperationException();
    }

    public KeyJar copy() {
        throw new UnsupportedOperationException();
    }

    public ArrayList keysByAlgAndUsage(String issuer, Object alg, String usage) {
        throw new UnsupportedOperationException();
    }

    public ArrayList getIssuerKeys(String issuer) {
        throw new UnsupportedOperationException();
    }

    public boolean equals(KeyJar other) {
        throw new UnsupportedOperationException();
    }

    public void removeOutdated(int when) {
        throw new UnsupportedOperationException();
    }
}
