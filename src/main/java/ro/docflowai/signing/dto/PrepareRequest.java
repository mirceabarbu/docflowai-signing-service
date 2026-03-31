package ro.docflowai.signing.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class PrepareRequest {
    @NotBlank public String pdfBase64;
    @NotBlank public String fieldName;
    @NotBlank public String signerName;
    public String signerRole;
    public String reason;
    public String location;
    public String contactInfo;
    @NotNull public Integer page;
    @NotNull public Float x;
    @NotNull public Float y;
    @NotNull public Float width;
    @NotNull public Float height;
    @NotNull public Boolean useSignedAttributes;
    @NotBlank public String subFilter;
    // b236: certificatul semnatarului (PEM) — necesar pentru signing-certificate-v2 în signedAttrs
    // Se trimite DOAR când e cunoscut înaintea hash-ului (fluxul b236: prepare după OAuth)
    public String signerCertificatePem;
}
