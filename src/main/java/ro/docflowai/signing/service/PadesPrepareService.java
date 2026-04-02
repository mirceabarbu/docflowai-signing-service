package ro.docflowai.signing.service;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfFormField;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfSigner;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalSignatureContainer;
import com.itextpdf.signatures.PdfSignatureAppearance;
import org.springframework.stereotype.Service;
import ro.docflowai.signing.dto.PrepareRequest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

@Service
public class PadesPrepareService {

    public byte[] prepare(PrepareRequest req) throws Exception {
        byte[] inputPdf = req.getPdfBytes();
        String fieldName = safe(req.getFieldName());
        Rectangle rect = safeRect(req.getRect());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfReader reader = new PdfReader(new ByteArrayInputStream(inputPdf));
        StampingPropertiesPreserve appendMode = new StampingPropertiesPreserve();

        PdfSigner signer = new PdfSigner(reader, baos, appendMode.get(), false);

        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance
                .setReason("Semnare DocFlowAI")
                .setLocation("Romania")
                .setReuseAppearance(false);

        if (rect != null && req.getPage() > 0) {
            appearance.setPageRect(rect).setPageNumber(req.getPage());
        }

        String signedAtText = ZonedDateTime.now(ZoneId.of("Europe/Bucharest"))
                .format(DateTimeFormatter.ofPattern("dd.MM.yyyy, HH:mm"));

        String appearanceText =
                safe(req.getSignerRole()) + "\n" +
                safe(req.getSignerFunction()) + "\n" +
                safe(req.getSignerName()) + "\n\n" +
                "Semnat digital QES\n" +
                signedAtText + "\n" +
                "DocFlowAI | STS Cloud QES";

        appearance.setLayer2Text(appearanceText);

        signer.setFieldName(fieldName);

        IExternalSignatureContainer blank = (is, os) -> new byte[0];
        signer.signExternalContainer(blank, 8192);

        return baos.toByteArray();
    }

    private String safe(String s) {
        return s == null ? "" : s.trim();
    }

    private Rectangle safeRect(float[] r) {
        if (r == null || r.length < 4) return null;
        return new Rectangle(r[0], r[1], r[2], r[3]);
    }

    // Small helper so append mode is explicit and easy to adjust if needed.
    private static class StampingPropertiesPreserve {
        public com.itextpdf.kernel.pdf.StampingProperties get() {
            return new com.itextpdf.kernel.pdf.StampingProperties().useAppendMode();
        }
    }
}
