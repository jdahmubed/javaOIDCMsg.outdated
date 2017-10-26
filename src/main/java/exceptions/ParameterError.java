package exceptions;

public class ParameterError extends Exception {

    private String message;

    public ParameterError(String message) {
        this.message = message;
    }

}
