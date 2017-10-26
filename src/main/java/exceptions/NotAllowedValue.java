package exceptions;

public class NotAllowedValue extends Exception {

    private String message;

    public NotAllowedValue(String message) {
        this.message = message;
    }

}
