package exceptions;

public class UpdateFailed extends Exception {

    private String message;

    public UpdateFailed(String message) {
        this.message = message;
    }

}
