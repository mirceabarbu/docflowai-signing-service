package ro.docflowai.signing.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ro.docflowai.signing.dto.PrepareRequest;
import ro.docflowai.signing.dto.PrepareResponse;

import java.security.MessageDigest;
import java.util.Base64;

@Service
public class PadesPrepareService extends Base64PdfSupport {

    @Value("${APP_MODE:scaffold}")
    private String mode;

    public PrepareResponse prepare(PrepareRequest request) {
        byte[] pdfBytes = decodeBase64(request.pdfBase64);
        String digest = sha256Base64(pdfBytes);

        PrepareResponse out = new PrepareResponse();
        out.preparedPdfBase64 = request.pdfBase64;
        out.documentDigestBase64 = digest;
        out.toBeSignedDigestBase64 = digest;
        out.fieldName = request.fieldName;
        out.usesSignedAttributes = request.useSignedAttributes;
        out.subFilter = request.subFilter;
        out.estimatedSignatureSize = 32768;
        out.mode = mode;
        out.warning = "Scaffold mode: digestul returnat este SHA-256 al PDF-ului brut. Înlocuiește cu logica PAdES externă reală înainte de producție.";
        return out;
    }

    private String sha256Base64(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(md.digest(data));
        } catch (Exception e) {
            throw new RuntimeException("Nu am putut calcula SHA-256", e);
        }
    }
}
