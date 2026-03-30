package ro.docflowai.signing.dto;

public class FinalizeResponse {
    public String signedPdfBase64;
    public Validation validation;
    public String mode;
    public String warning;

    public static class Validation {
        public Boolean byteRangeOk;
        public Boolean signatureEmbedded;
        public String fieldName;
    }
}
