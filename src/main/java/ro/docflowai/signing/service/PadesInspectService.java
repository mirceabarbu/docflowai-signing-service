package ro.docflowai.signing.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ro.docflowai.signing.dto.InspectRequest;
import ro.docflowai.signing.dto.InspectResponse;

@Service
public class PadesInspectService extends Base64PdfSupport {

    @Value("${APP_MODE:scaffold}")
    private String mode;

    public InspectResponse inspect(InspectRequest request) {
        byte[] pdfBytes = decodeBase64(request.pdfBase64);
        InspectResponse out = new InspectResponse();
        out.pdfBytes = pdfBytes.length;
        out.base64Decoded = true;
        out.mode = mode;
        out.notes.add("Scaffold mode: inspecția nu parsează încă semnături PDF reale.");
        out.notes.add("Pasul următor este implementarea prepare/finalize pe iText external signing.");
        return out;
    }
}
