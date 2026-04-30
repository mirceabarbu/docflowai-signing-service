package ro.docflowai.signing.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class PrepareRequest {
    @NotBlank public String pdfBase64;
    @NotBlank public String fieldName;
    @NotBlank public String signerName;
    public String signerRole;
    public String signerFunction;
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
    public String signerCertificatePem;
    // b240: index 0=primul semnatar, 1=al doilea, etc.
    public Integer signerIndex;
    // b242: true = câmpul /Sig există deja în PDF (pre-creat la flow creation)
    public Boolean fieldAlreadyExists;
    // b253: "cartus" (default, flux tabel) = 6 linii cu chenar
    //        "ancore"  (flux ancore STS)   = 2 linii simple în câmpul AcroForm existent
    public String appearanceMode;
    // b254: text delegare — afișat ca linie 7 în cartuș dacă != null
    //        Format trimis de Node: "delegat de Nume - Funcție"
    public String delegatedFromText;
}
