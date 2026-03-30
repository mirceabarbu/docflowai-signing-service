package ro.docflowai.signing.exception;

import java.time.OffsetDateTime;

public class ApiError {
    public String error;
    public String message;
    public String ts = OffsetDateTime.now().toString();

    public ApiError(String error, String message) {
        this.error = error;
        this.message = message;
    }
}
