package exceptions;

public class MissingRequiredAttribute extends Exception {

    private String message;

    public MissingRequiredAttribute(String message) {
        this.message = message;
    }

}
