package ro.docflowai.signing.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public class FinalizeRequest {
    @NotBlank public String preparedPdfBase64;
    @NotBlank public String fieldName;
    @NotBlank public String signByteBase64;
    @NotBlank public String certificatePem;
    public List<String> certificateChainPem;
    @NotNull public Boolean useSignedAttributes;
    @NotBlank public String subFilter;
}
