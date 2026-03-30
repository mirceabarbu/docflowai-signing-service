package ro.docflowai.signing.dto;

public class PrepareResponse {
    public String preparedPdfBase64;
    public String documentDigestBase64;
    public String toBeSignedDigestBase64;
    public String fieldName;
    public Boolean usesSignedAttributes;
    public String subFilter;
    public Integer estimatedSignatureSize;
    public String mode;
    public String warning;
}
