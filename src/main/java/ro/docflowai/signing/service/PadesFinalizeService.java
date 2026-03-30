package ro.docflowai.signing.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ro.docflowai.signing.dto.FinalizeRequest;
import ro.docflowai.signing.dto.FinalizeResponse;

@Service
public class PadesFinalizeService extends Base64PdfSupport {

    @Value("${APP_MODE:scaffold}")
    private String mode;

    public FinalizeResponse finalizeSignature(FinalizeRequest request) {
        FinalizeResponse out = new FinalizeResponse();
        out.signedPdfBase64 = request.preparedPdfBase64;
        out.mode = mode;
        out.warning = "Scaffold mode: PDF-ul returnat este cel pregătit, fără CMS/PAdES valid inserat. Înlocuiește cu finalize real înainte de producție.";

        FinalizeResponse.Validation validation = new FinalizeResponse.Validation();
        validation.byteRangeOk = false;
        validation.signatureEmbedded = false;
        validation.fieldName = request.fieldName;
        out.validation = validation;
        return out;
    }
}
