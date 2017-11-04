package exceptions;

public class ValueError extends Exception {

    private String message;

    public ValueError(String message) {
        this.message = message;
    }

}
