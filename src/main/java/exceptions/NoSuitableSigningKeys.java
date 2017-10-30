package exceptions;

public class NoSuitableSigningKeys extends Exception {

    private String message;

    public NoSuitableSigningKeys(String message) {
        this.message = message;
    }

}
