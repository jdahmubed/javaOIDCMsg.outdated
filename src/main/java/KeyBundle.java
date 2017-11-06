import com.sun.deploy.net.HttpResponse;
import exceptions.*;
import org.json.JSONObject;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.security.Key;
import java.util.List;
import java.util.Map;

public class KeyBundle {

    public KeyBundle(Map<String,Object> keys, String source, int cacheTime, boolean verifySSL,
                     String fileFormat, String keyType, KeyUsage keyUsage) {
        throw new UnsupportedOperationException();
    }

    public void doKeys(Map<String,Object> keys) throws KeyError, JWKException {
        throw new UnsupportedOperationException();
    }

    public void doLocalJwk(String fileName) throws KeyError, UpdateFailed {
        throw new UnsupportedOperationException();
    }

    public void doLocalDer(String fileName, String keyType, KeyUsage keyUsage) throws NotImplementedException {
        throw new UnsupportedOperationException();
    }

    public boolean doRemote() throws UpdateFailed, KeyError {
        throw new UnsupportedOperationException();
    }

    private JSONObject parseRemoteResponse(HttpResponse response) throws KeyError, ValueError {
        throw new UnsupportedOperationException();
    }

    private boolean upToDate() {
        throw new UnsupportedOperationException();
    }

    public boolean update() throws ValueError {
        throw new UnsupportedOperationException();
    }

    public Map<String,Object> get(String typ) {
        throw new UnsupportedOperationException();
    }

    public Map<String,Object> getKeys() {
        throw new UnsupportedOperationException();
    }

    public List<Object> getActiveKeys() {
        throw new UnsupportedOperationException();
    }

    public void removeKeysByType(String typ) {
        throw new UnsupportedOperationException();
    }

    public String toString() {
        throw new UnsupportedOperationException();
    }

    public String jwks(boolean isPrivate) {
        throw new UnsupportedOperationException();
    }

    public void append(Key key) {
        throw new UnsupportedOperationException();
    }

    public void remove(Key key) throws ValueError{
        throw new UnsupportedOperationException();
    }

    public int getLength() {
        throw new UnsupportedOperationException();
    }

    public Key getKeyWithKid(Object kid) {
        throw new UnsupportedOperationException();
    }

    public List<Object> getKids() {
        throw new UnsupportedOperationException();
    }

    public void markAsInactive(Object kid) {
        throw new UnsupportedOperationException();
    }

    public void removeOutdated(float after, int when) throws TypeError {
        throw new UnsupportedOperationException();
    }


    //----Not part of KeyBundle class, but I thought I should include these methods
    public KeyBundle keyBundleFromLocalFile(String filename, String type, KeyUsage usage) {
        throw new UnsupportedOperationException();
    }

    public void dumpJwks(List<KeyBundle> kbl, String target, boolean isPrivate) {
        throw new UnsupportedOperationException();
    }


}
