package ro.docflowai.signing.service;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.SignatureUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ro.docflowai.signing.dto.InspectRequest;
import ro.docflowai.signing.dto.InspectResponse;

import java.io.ByteArrayInputStream;
import java.util.List;

@Service
public class PadesInspectService extends Base64PdfSupport {

    @Value("${APP_MODE:real}")
    private String mode;

    public InspectResponse inspect(InspectRequest request) {
        try {
            byte[] pdfBytes = decodeBase64(request.pdfBase64);
            InspectResponse out = new InspectResponse();
            out.pdfBytes = pdfBytes.length;
            out.base64Decoded = true;
            out.mode = mode;

            PdfDocument pdfDocument = new PdfDocument(new PdfReader(new ByteArrayInputStream(pdfBytes)));
            SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);
            List<String> names = signatureUtil.getSignatureNames();
            out.notes.add("Semnături găsite: " + names.size());
            for (String name : names) {
                PdfPKCS7 pkcs7 = signatureUtil.readSignatureData(name);
                boolean integrity = pkcs7.verifySignatureIntegrityAndAuthenticity();
                out.notes.add("Field=" + name
                        + "; integrity=" + integrity
                        + "; algo=" + pkcs7.getSignatureAlgorithmName()
                        + "; chain=" + (pkcs7.getSignCertificateChain() == null ? 0 : pkcs7.getSignCertificateChain().length)
                        + "; tsa=" + !pkcs7.getTimeStampDate().toString().contains("UNDEFINED"));
            }
            pdfDocument.close();
            return out;
        } catch (Exception e) {
            throw new RuntimeException("inspect PAdES a eșuat", e);
        }
    }
}
