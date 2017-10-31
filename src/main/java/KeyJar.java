import exceptions.KeyError;
import exceptions.KeyIOError;
import exceptions.MessageException;
import org.omg.CORBA.DynAnyPackage.InvalidValue;

import java.security.Key;
import java.util.*;

public class KeyJar {

    private Map<String,Object> issuerKeys;
    private boolean verifySSL;
    private long removeAfter;

    public KeyJar(Map<String,Object> issuerKeys, boolean verifySSL, long removeAfter) {
        this.issuerKeys = issuerKeys;
        this.verifySSL = verifySSL;
        this.removeAfter = removeAfter;
    }

    public String repr() {
        throw new UnsupportedOperationException();
    }

    public KeyBundle add(String issuer, String url, Map<String,Object> args) throws KeyError{
        throw new UnsupportedOperationException();
    }

    public void addSymmetric(String issuer, String key, List usage) {
        throw new UnsupportedOperationException();
    }

    public void addKb(String issuer, KeyBundle kb) throws KeyError{
        throw new UnsupportedOperationException();
    }

    public void setItem(String issuer, KeyBundle val) {
        throw new UnsupportedOperationException();
    }

    public Set items() {
        throw new UnsupportedOperationException();
    }

    public List get(String keyUse, String keyType, String issuer, Object kid, Map<String,Object> args)
        throws KeyError, AssertionError{
        throw new UnsupportedOperationException();
    }

    public List getSigningKey(String keyType, String owner, Object kid, Map<String,Object> args) {
        throw new UnsupportedOperationException();
    }

    public List getVerifyKey(String keyType, String owner, Object kid, Map<String,Object> args) {
        throw new UnsupportedOperationException();
    }

    public List getEncryptKey(String keyType, String owner, Object kid, Map<String,Object> args) {
        throw new UnsupportedOperationException();
    }

    public List getDecryptKey(String keyType, String owner, Object kid, Map<String,Object> args) {
        throw new UnsupportedOperationException();
    }

    public Key getKeyByKid(String kid, String owner) {
        throw new UnsupportedOperationException();
    }

    public boolean contains(Object item) {
        throw new UnsupportedOperationException();
    }

    public List<Key> xKeys(String var, String part) {
        throw new UnsupportedOperationException();
    }

    public List<Key> verifyKeys(String part) {
        throw new UnsupportedOperationException();
    }

    public List<Key> decryptKeys(String part) {
        throw new UnsupportedOperationException();
    }

    public List<KeyBundle> getItem(String issuer) throws KeyError{
        throw new UnsupportedOperationException();
    }

    public void removeKey(String issuer, String keyType, Key key) throws KeyError {
        throw new UnsupportedOperationException();
    }

    public void update(KeyJar kj) throws KeyError{
        throw new UnsupportedOperationException();
    }

    public String matchOwner(String url) throws KeyIOError {
        throw new UnsupportedOperationException();
    }

    public String toString() {
        throw new UnsupportedOperationException();
    }

    public List getKeys() {
        throw new UnsupportedOperationException();
    }

    public void loadKeys(Map<String,String> pcr, String issuer, boolean replace)
        throws MessageException, KeyError
    {
        throw new UnsupportedOperationException();
    }

    public KeyBundle find(String source, String issuer) throws KeyError {
        throw new UnsupportedOperationException();
    }

    public List dumpIssuerKeys(String issuer) throws KeyError {
        throw new UnsupportedOperationException();
    }

    public Map<String,Object> exportJwks(boolean isPrivate, String issuer) {
        throw new UnsupportedOperationException();
    }

    public void importJwks(Map<String,Object> jwks, String issuer) throws KeyError, InvalidValue {
        throw new UnsupportedOperationException();
    }

    public void addKeyJar(KeyJar keyJar) throws KeyError {
        throw new UnsupportedOperationException();
    }

    public Map<String, Object> dump() {
        throw new UnsupportedOperationException();
    }

    public void restore(Map<String,Object> info) {
        throw new UnsupportedOperationException();
    }

    public KeyJar copy() {
        throw new UnsupportedOperationException();
    }

    public List keysByAlgAndUsage(String issuer, String alg, String usage) {
        throw new UnsupportedOperationException();
    }

    public List getIssuerKeys(String issuer) {
        throw new UnsupportedOperationException();
    }

    public boolean equals(KeyJar other) {
        throw new UnsupportedOperationException();
    }

    public void removeOutdated(int when) {
        throw new UnsupportedOperationException();
    }
}
