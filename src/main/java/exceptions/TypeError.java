package exceptions;

public class TypeError extends Exception {

    private String message;

    public TypeError(String message) {
        this.message = message;
    }

}