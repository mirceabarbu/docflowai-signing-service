package ro.docflowai.signing.service;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfSignatureFormField;
import com.itextpdf.forms.fields.SignatureFormFieldBuilder;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ro.docflowai.signing.dto.CreateFieldsRequest;
import ro.docflowai.signing.dto.CreateFieldsResponse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

/**
 * PadesCreateFieldsService b251
 *
 * Creeaza campuri AcroForm /Sig folosind iText (NU pdf-lib).
 *
 * Motivul pentru care pdf-lib NU poate crea campuri /Sig compatibile cu PAdES multi-sign:
 * pdf-lib creeaza Widget obiecte incomplete (fara /AP, /DR etc.).
 * Cand iText deschide documentul pentru semnare, "repara" aceste obiecte incomplete
 * scriind versiuni noi in incremental update. Adobe detecteaza aceste versiuni noi
 * ca "modificari" ale documentului si invalideaza semnaturile anterioare.
 *
 * Solutia: iText creeaza campurile /Sig cu toate entry-urile necesare.
 * La semnare ulterioara, iText recunoaste propriile campuri si NU mai are nevoie
 * de "reparare" → scrie MINIM in incremental update → semnaturile anterioare raman valide.
 */
@Service
public class PadesCreateFieldsService extends Base64PdfSupport {

    private static final Logger log = LoggerFactory.getLogger(PadesCreateFieldsService.class);

    @Value("${APP_MODE:real}")
    private String mode;

    public CreateFieldsResponse createFields(CreateFieldsRequest request) {
        try {
            byte[] pdfBytes = decodeBase64(request.pdfBase64);
            log.info("createFields: PDF input size={} bytes, fields={}", pdfBytes.length,
                    request.fields != null ? request.fields.size() : 0);

            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // Folosim append mode pentru a pastra vizualul pdf-lib intact
            PdfReader reader  = new PdfReader(new ByteArrayInputStream(pdfBytes));
            PdfWriter writer  = new PdfWriter(out);
            PdfDocument pdfDoc = new PdfDocument(reader, writer,
                    new StampingProperties().useAppendMode());

            PdfAcroForm acroForm = PdfAcroForm.getAcroForm(pdfDoc, true);
            // SigFlags = 3 (SignaturesExist=1 | AppendOnly=2)
            acroForm.setSignatureFlags(3);

            int created = 0;
            if (request.fields != null) {
                for (CreateFieldsRequest.FieldDef fd : request.fields) {
                    if (fd == null || fd.fieldName == null || fd.fieldName.isBlank()) continue;

                    int pageNum = fd.page != null ? fd.page : 1;
                    float x = fd.x != null ? fd.x : 0f;
                    float y = fd.y != null ? fd.y : 0f;
                    float w = fd.w != null ? fd.w : 150f;
                    float h = fd.h != null ? fd.h : 50f;

                    Rectangle rect = new Rectangle(x, y, w, h);

                    // iText SignatureFormFieldBuilder creeaza un camp /Sig COMPLET
                    // (cu toate entry-urile necesare conform spec PDF/PAdES)
                    PdfSignatureFormField sigField = new SignatureFormFieldBuilder(pdfDoc, fd.fieldName)
                            .setPage(pageNum)
                            .setWidgetRectangle(rect)
                            .createSignature();

                    // Camp invizibil — aspectul vizual vine din celula cartusului desenata de Node
                    // Campul va fi completat de Java la semnare (appearance text adaugat atunci)
                    acroForm.addField(sigField, pdfDoc.getPage(pageNum));
                    created++;
                    log.info("createFields: camp '{}' creat la ({},{}) {}x{} page={}",
                            fd.fieldName, x, y, w, h, pageNum);
                }
            }

            pdfDoc.close();

            CreateFieldsResponse resp = new CreateFieldsResponse();
            resp.pdfBase64    = Base64.getEncoder().encodeToString(out.toByteArray());
            resp.fieldsCreated = created;
            resp.mode         = mode;

            log.info("createFields: {} campuri create, PDF output size={} bytes",
                    created, out.size());
            return resp;

        } catch (Exception e) {
            log.error("createFields: EROARE — {}", e.getMessage(), e);
            throw new RuntimeException("createFields a esuat", e);
        }
    }
}
