package ro.docflowai.signing.service;

import com.itextpdf.io.font.constants.StandardFonts;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfArray;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.kernel.pdf.xobject.PdfFormXObject;
import com.itextpdf.signatures.IExternalSignatureContainer;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ro.docflowai.signing.dto.PrepareRequest;
import ro.docflowai.signing.dto.PrepareResponse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;

/**
 * PadesPrepareService b253
 *
 * MODIFICARE: Aparență vizuală custom pentru câmpul de semnătură QES.
 * Layout (6 linii + chenar):
 *   1. ROL/ATRIBUT   (bold, negru)
 *   2. Functie        (regular, gri-inchis)
 *   3. Semnat digital QES  (bold, albastru)
 *   4. NUME           (bold, negru) — extras din certificat (CN)
 *   5. dd.MM.yyyy, HH:mm:ss  (regular, gri)
 *   6. DocFlowAI | STS Cloud QES  (mic, gri)
 *
 * Chenarul NU invalidează semnătura: aparența vizuală (XObject n2/layer2) este
 * inclusă în ByteRange-ul hash-ului PAdES — este semnat digital împreună cu
 * conținutul documentului. Orice modificare post-signing a apariției ar invalida
 * semnătura, ceea ce este CORECT conform standardului PAdES/eIDAS.
 *
 * ARHITECTURA MULTI-SEMNATAR (păstrată identic față de b242):
 * Câmpurile /Sig pre-create de Node.js (fieldAlreadyExists=true) → Java NU
 * modifică AcroForm Fields / Page Annots → semnăturile anterioare rămân valide.
 */
@Service
public class PadesPrepareService extends Base64PdfSupport {

    private static final Logger log = LoggerFactory.getLogger(PadesPrepareService.class);

    @Value("${APP_MODE:real}")
    private String mode;

    // ── Layout constants ─────────────────────────────────────────────────────
    private static final float PAD_X     = 4.5f;  // left padding (pt)
    private static final float PAD_TOP   = 3.0f;  // gap between top border and first baseline
    private static final float LINE_H    = 7.5f;  // spacing between baselines (pt)
    private static final float BORDER_W  = 0.7f;  // border line width (pt)
    private static final float BORDER_IN = 0.8f;  // border inset from XObject edge (pt)

    // Font sizes (pt)
    private static final float FS_ROLE = 6.5f;
    private static final float FS_FUNC = 6.0f;
    private static final float FS_QES  = 6.0f;
    private static final float FS_NAME = 6.5f;
    private static final float FS_DATE = 5.5f;
    private static final float FS_FOOT = 5.0f;

    // Colors
    private static final DeviceRgb C_BLACK      = new DeviceRgb(0.05f, 0.05f, 0.05f);
    private static final DeviceRgb C_DARK_GRAY  = new DeviceRgb(0.25f, 0.25f, 0.25f);
    private static final DeviceRgb C_GRAY       = new DeviceRgb(0.45f, 0.45f, 0.45f);
    private static final DeviceRgb C_BLUE       = new DeviceRgb(0.08f, 0.28f, 0.60f);
    private static final DeviceRgb C_BORDER     = new DeviceRgb(0.35f, 0.35f, 0.35f);

    // ── prepare() ────────────────────────────────────────────────────────────

    public PrepareResponse prepare(PrepareRequest request) {
        try {
            boolean fieldExists = Boolean.TRUE.equals(request.fieldAlreadyExists);
            log.info("prepare: signerIndex={}, fieldName={}, fieldAlreadyExists={}, hasCert={}",
                    request.signerIndex, request.fieldName, fieldExists,
                    request.signerCertificatePem != null && !request.signerCertificatePem.isBlank());

            // Certificat pentru signing-certificate-v2 în signedAttrs
            byte[] signerCertDer = null;
            if (request.signerCertificatePem != null && !request.signerCertificatePem.isBlank()) {
                signerCertDer = DerCmsSupport.pemToDer(request.signerCertificatePem);
                log.info("prepare: signing-certificate-v2 va fi inclus in signedAttrs");
            } else {
                log.warn("prepare: signerCertificatePem absent — signedAttrs fara signing-certificate-v2");
            }

            byte[] pdfBytes = decodeBase64(request.pdfBase64);
            ByteArrayOutputStream preparedOut = new ByteArrayOutputStream();
            PdfReader reader = new PdfReader(new ByteArrayInputStream(pdfBytes));
            PdfSigner signer = new PdfSigner(reader, preparedOut,
                    new StampingProperties().useAppendMode());
            signer.setFieldName(request.fieldName);

            // NOT_CERTIFIED: ESENTIAL pentru multi-semnatar
            signer.setCertificationLevel(PdfSigner.NOT_CERTIFIED);

            // Dimensiuni cartus — trimise ÎNTOTDEAUNA de Node.js indiferent de fieldAlreadyExists
            float w = request.width  != null ? request.width  : 180f;
            float h = request.height != null ? request.height : 50f;

            PdfSignatureAppearance appearance = signer.getSignatureAppearance();
            if (request.reason      != null) appearance.setReason(request.reason);
            if (request.location    != null) appearance.setLocation(request.location);
            if (request.contactInfo != null) appearance.setContact(request.contactInfo);

            if (!fieldExists) {
                // Câmp NOU: setăm rect-ul explicit
                appearance.setPageRect(new Rectangle(
                        request.x != null ? request.x : 30f,
                        request.y != null ? request.y : 30f,
                        w, h));
                appearance.setPageNumber(request.page != null ? request.page : 1);
                log.info("prepare: câmp NOU la ({},{}) {}x{}", request.x, request.y, w, h);
            } else {
                // Câmp EXISTENT: NU setăm rect — iText folosește widget-ul existent
                // AcroForm Fields și Page Annots rămân NEATINSE în incremental update
                log.info("prepare: câmp EXISTENT folosit — fara modificare AcroForm/Annots");
            }

            // ── Aparență vizuală custom ─────────────────────────────────────
            // Setăm layer2Text=" " (un spațiu): iText va face APPEND pe n2 XObject
            // cu un caracter spațiu invizibil. Conținutul nostru (desenat înainte)
            // rămâne vizibil. Chenarul și textul sunt în ByteRange-ul hash-ului PAdES.
            appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
            appearance.setLayer2Text(" ");

            // Obținem XObject-ul n2 (layer2) și îi setăm BBox corect
            PdfFormXObject layer2 = appearance.getLayer2();
            layer2.put(PdfName.BBox, new PdfArray(new float[]{0f, 0f, w, h}));

            // Desenăm conținutul custom (chenar + 6 linii text)
            drawCustomCartus(layer2, signer.getDocument(), w, h, request);

            // ── Hash capture ────────────────────────────────────────────────
            final byte[] signerCertDerFinal = signerCertDer;
            CapturingBlankContainer blank = new CapturingBlankContainer(
                    request.subFilter,
                    Boolean.TRUE.equals(request.useSignedAttributes),
                    signerCertDerFinal
            );
            int estimatedSignatureSize = 65536;
            signer.signExternalContainer(blank, estimatedSignatureSize);

            byte[] preparedBytes = preparedOut.toByteArray();

            // ── DIAGNOSTIC ──────────────────────────────────────────────────
            if (preparedBytes.length < pdfBytes.length) {
                log.error("DIAGNOSTIC CRITIC: preparedBytes < pdfBytes ({} < {}) — iText a redus PDF!",
                        preparedBytes.length, pdfBytes.length);
            } else {
                boolean originalPreserved = Arrays.equals(pdfBytes,
                        Arrays.copyOf(preparedBytes, pdfBytes.length));
                if (originalPreserved) {
                    log.info("DIAGNOSTIC OK: primii {} bytes (original) IDENTICI — sig anterioare vor fi valide",
                            pdfBytes.length);
                } else {
                    int firstDiff = -1;
                    for (int di = 0; di < pdfBytes.length; di++) {
                        if (pdfBytes[di] != preparedBytes[di]) { firstDiff = di; break; }
                    }
                    log.error("DIAGNOSTIC CRITIC: bytes modificate la pozitia {} — sig anterioare INVALIDE!",
                            firstDiff);
                }
            }
            log.info("prepare: OK — original={}b, prepared={}b, delta={}b, fieldName={}, hasCert={}",
                    pdfBytes.length, preparedBytes.length, preparedBytes.length - pdfBytes.length,
                    request.fieldName, signerCertDer != null);
            // ── END DIAGNOSTIC ──────────────────────────────────────────────

            PrepareResponse out = new PrepareResponse();
            out.preparedPdfBase64      = Base64.getEncoder().encodeToString(preparedBytes);
            out.documentDigestBase64   = Base64.getEncoder().encodeToString(blank.documentDigest);
            out.toBeSignedDigestBase64 = blank.toBeSignedDigestBase64;
            out.fieldName              = request.fieldName;
            out.usesSignedAttributes   = request.useSignedAttributes;
            out.subFilter              = request.subFilter;
            out.estimatedSignatureSize = estimatedSignatureSize;
            out.mode                   = mode;
            out.warning                = signerCertDer == null
                    ? "signerCertificatePem absent — signing-certificate-v2 nu e inclus"
                    : null;
            return out;

        } catch (Exception e) {
            log.error("prepare: EROARE — {}", e.getMessage(), e);
            throw new RuntimeException("prepare PAdES a esuat", e);
        }
    }

    // ── Desenare cartus custom ────────────────────────────────────────────────

    /**
     * Desenează aparența vizuală a câmpului de semnătură QES:
     *   chenar + 6 linii text (rol, functie, "Semnat digital QES", nume, data/ora, footer).
     *
     * Sistemul de coordonate PDF: origine (0,0) la colțul STÂNGA-JOS al XObject-ului.
     * y crește ÎN SUS. Deci prima linie (sus) are y-baseline = h - PAD_TOP - fontSize.
     */
    private void drawCustomCartus(PdfFormXObject layer2, com.itextpdf.kernel.pdf.PdfDocument pdfDoc,
                                  float w, float h, PrepareRequest req) {
        try {
            PdfFont fontBold    = PdfFontFactory.createFont(StandardFonts.HELVETICA_BOLD);
            PdfFont fontRegular = PdfFontFactory.createFont(StandardFonts.HELVETICA);

            // Texte normalize (fără diacritice — Standard Fonts nu suportă Unicode extins)
            String txtRole = normalize(
                    (req.signerRole == null || req.signerRole.isBlank()) ? "SEMNATAR"
                            : req.signerRole.toUpperCase());
            String txtFunc = normalize(
                    (req.signerFunction == null || req.signerFunction.isBlank()) ? ""
                            : req.signerFunction);
            String txtName = normalize(
                    (req.signerName == null || req.signerName.isBlank()) ? "Semnatar"
                            : req.signerName);

            String dateStr = ZonedDateTime.now(ZoneId.of("Europe/Bucharest"))
                    .format(DateTimeFormatter.ofPattern("dd.MM.yyyy, HH:mm:ss"));

            PdfCanvas canvas = new PdfCanvas(layer2, pdfDoc);

            // ── 1. Chenar ──────────────────────────────────────────────────
            canvas.saveState()
                  .setStrokeColor(C_BORDER)
                  .setLineWidth(BORDER_W)
                  .rectangle(BORDER_IN, BORDER_IN, w - 2 * BORDER_IN, h - 2 * BORDER_IN)
                  .stroke()
                  .restoreState();

            // ── 2. Linii text ──────────────────────────────────────────────
            // Baseline-uri (y de jos în sus):
            // Linia 1 este CEA MAI DE SUS: y1 = h - PAD_TOP - FS_ROLE
            float y1 = h - PAD_TOP - FS_ROLE;          // rol
            float y2 = y1 - LINE_H;                    // functie
            float y3 = y2 - LINE_H;                    // "Semnat digital QES"
            float y4 = y3 - LINE_H;                    // nume
            float y5 = y4 - LINE_H;                    // data, ora
            float y6 = y5 - (LINE_H - 0.5f);           // footer (puțin mai strans)

            // Linia 1: ROL/ATRIBUT — bold, negru
            canvas.beginText()
                  .setFontAndSize(fontBold, FS_ROLE)
                  .setFillColor(C_BLACK)
                  .moveText(PAD_X, y1)
                  .showText(truncate(txtRole, w - PAD_X * 2, fontBold, FS_ROLE))
                  .endText();

            // Linia 2: FUNCTIE — regular, gri-închis (dacă există)
            if (!txtFunc.isEmpty()) {
                canvas.beginText()
                      .setFontAndSize(fontRegular, FS_FUNC)
                      .setFillColor(C_DARK_GRAY)
                      .moveText(PAD_X, y2)
                      .showText(truncate(txtFunc, w - PAD_X * 2, fontRegular, FS_FUNC))
                      .endText();
            }

            // Linia 3: "Semnat digital QES" — bold, albastru
            canvas.beginText()
                  .setFontAndSize(fontBold, FS_QES)
                  .setFillColor(C_BLUE)
                  .moveText(PAD_X, y3)
                  .showText("Semnat digital QES")
                  .endText();

            // Linia 4: NUME — bold, negru
            canvas.beginText()
                  .setFontAndSize(fontBold, FS_NAME)
                  .setFillColor(C_BLACK)
                  .moveText(PAD_X, y4)
                  .showText(truncate(txtName, w - PAD_X * 2, fontBold, FS_NAME))
                  .endText();

            // Linia 5: DATA ORA — regular, gri
            canvas.beginText()
                  .setFontAndSize(fontRegular, FS_DATE)
                  .setFillColor(C_GRAY)
                  .moveText(PAD_X, y5)
                  .showText(dateStr)
                  .endText();

            // Linia 6: FOOTER — mic, gri
            canvas.beginText()
                  .setFontAndSize(fontRegular, FS_FOOT)
                  .setFillColor(C_GRAY)
                  .moveText(PAD_X, y6)
                  .showText("DocFlowAI | STS Cloud QES")
                  .endText();

            canvas.release();

            log.info("drawCustomCartus: OK — {}x{} pt, role='{}', func='{}', name='{}'",
                    w, h, txtRole, txtFunc, txtName);

        } catch (Exception e) {
            log.error("drawCustomCartus EROARE — va folosi aparenta text simplu: {}", e.getMessage(), e);
            // Fallback: lăsăm layer2 fără conținut custom (doar spațiul din setLayer2Text)
        }
    }

    /**
     * Trunchiaza un string pentru a se incadra în maxWidth puncte la fontSize dat.
     * Simplu: estimare liniară pe baza lățimii medii a unui caracter Helvetica.
     */
    private static String truncate(String text, float maxWidth, PdfFont font, float fontSize) {
        if (text == null || text.isEmpty()) return "";
        // Estimare lățime: Helvetica ~0.55 * fontSize per caracter mediu
        float charW = fontSize * 0.55f;
        int maxChars = (int) (maxWidth / charW);
        if (maxChars <= 0) return "";
        if (text.length() <= maxChars) return text;
        return text.substring(0, Math.max(0, maxChars - 2)) + "..";
    }

    // ── Normalize diacritice ──────────────────────────────────────────────────

    private String normalize(String s) {
        return s == null ? "" : s
                .replace("ă", "a").replace("â", "a").replace("î", "i")
                .replace("ș", "s").replace("ş", "s")
                .replace("ț", "t").replace("ţ", "t")
                .replace("Ă", "A").replace("Â", "A").replace("Î", "I")
                .replace("Ș", "S").replace("Ş", "S")
                .replace("Ț", "T").replace("Ţ", "T");
    }

    // ── CapturingBlankContainer ───────────────────────────────────────────────

    static class CapturingBlankContainer implements IExternalSignatureContainer {
        private final String subFilter;
        private final boolean useSignedAttributes;
        private final byte[] signingCertDer;
        byte[] documentDigest;
        String toBeSignedDigestBase64;

        CapturingBlankContainer(String subFilter, boolean useSignedAttributes, byte[] signingCertDer) {
            this.subFilter           = subFilter;
            this.useSignedAttributes = useSignedAttributes;
            this.signingCertDer      = signingCertDer;
        }

        @Override
        public byte[] sign(InputStream data) {
            documentDigest = DerCmsSupport.sha256(data);
            if (useSignedAttributes) {
                byte[] signedAttrs = DerCmsSupport.buildSignedAttrsDer(documentDigest, signingCertDer);
                toBeSignedDigestBase64 = DerCmsSupport.calcSignedAttrsHashBase64(signedAttrs);
            } else {
                toBeSignedDigestBase64 = Base64.getEncoder().encodeToString(documentDigest);
            }
            return new byte[0];
        }

        @Override
        public void modifySigningDictionary(PdfDictionary signDic) {
            signDic.put(PdfName.Filter, PdfName.Adobe_PPKLite);
            signDic.put(PdfName.SubFilter, new PdfName(subFilter));
        }
    }
}
