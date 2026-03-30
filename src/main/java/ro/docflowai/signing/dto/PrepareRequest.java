package ro.docflowai.signing.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;

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

    // optional, used when caller wants signedAttrs aligned with signer certificate chain
    public String certificatePem;
    public List<String> certificateChainPem;
}
