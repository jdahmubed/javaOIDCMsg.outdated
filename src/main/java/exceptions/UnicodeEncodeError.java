package exceptions;

public class UnicodeEncodeError extends Exception {

    private String message;

    public UnicodeEncodeError(String message) {
        this.message = message;
    }

}