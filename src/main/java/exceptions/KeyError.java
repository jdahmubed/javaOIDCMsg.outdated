package exceptions;

public class KeyError extends Exception {

    private String message;

    public KeyError(String message) {
        this.message = message;
    }

}
