package exceptions;

public class JWKException  extends Exception {

    private String message;

    public JWKException(String message) {
        this.message = message;
    }

}
