package exceptions;

public class KeyIOError extends Exception {

    private String message;

    public KeyIOError(String message) {
        this.message = message;
    }

}
