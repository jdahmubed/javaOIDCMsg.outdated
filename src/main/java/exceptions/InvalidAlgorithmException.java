package exceptions;

public class InvalidAlgorithmException extends Exception {

    private String message;

    public InvalidAlgorithmException(String message) {
        this.message = message;
    }

}
