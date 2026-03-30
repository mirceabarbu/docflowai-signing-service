package ro.docflowai.signing.service;

import java.util.Base64;

public abstract class Base64PdfSupport {
    protected byte[] decodeBase64(String value) {
        return Base64.getDecoder().decode(value);
    }

    protected String encodeBase64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }
}
