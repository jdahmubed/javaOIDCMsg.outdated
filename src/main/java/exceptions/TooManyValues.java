package exceptions;

public class TooManyValues extends Exception {

    private String message;

    public TooManyValues(String message) {
        this.message = message;
    }

}
