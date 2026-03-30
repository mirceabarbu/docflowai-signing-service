package ro.docflowai.signing.dto;

import jakarta.validation.constraints.NotBlank;

public class InspectRequest {
    @NotBlank public String pdfBase64;
}
