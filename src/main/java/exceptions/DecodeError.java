package exceptions;

public class DecodeError extends Exception {

    private String message;

    public DecodeError(String message) {
        this.message = message;
    }

}

