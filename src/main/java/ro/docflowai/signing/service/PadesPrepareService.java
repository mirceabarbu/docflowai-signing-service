package ro.docflowai.signing.service;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
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
import java.util.Arrays;
import java.util.Base64;

/**
 * PadesPrepareService b242
 *
 * ARHITECTURA CORECTA PAdES MULTI-SEMNATAR:
 *
 * Câmpurile AcroForm /Sig sunt pre-create de Node.js la creare flux (O SINGURA DATA).
 * Java primește fieldAlreadyExists=true → NU crează câmp nou → NU modifcă AcroForm Fields
 * → NU modifică Page Annots → incremental update MINIM.
 *
 * Rezultat: semnăturile anterioare rămân garantat valide.
 *
 * Când fieldAlreadyExists=false (fallback, câmp nou): comportament identic cu b241.
 */
@Service
public class PadesPrepareService extends Base64PdfSupport {

    private static final Logger log = LoggerFactory.getLogger(PadesPrepareService.class);

    @Value("${APP_MODE:real}")
    private String mode;

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
            PdfSigner signer = new PdfSigner(reader, preparedOut, new StampingProperties().useAppendMode());
            signer.setFieldName(request.fieldName);

            // NOT_CERTIFIED: ESENTIAL pentru multi-semnatar
            // Fara aceasta, /DocMDP restrictionează documentul si Adobe
            // invalideaza semnăturile anterioare la adaugarea uneia noi
            signer.setCertificationLevel(PdfSigner.NOT_CERTIFIED);

            if (!fieldExists) {
                // Câmp NOU: setăm rect-ul și appearance
                // Cazul fallback sau flux fără pre-creare câmpuri
                PdfSignatureAppearance appearance = signer.getSignatureAppearance();
                appearance.setPageRect(new Rectangle(
                        request.x != null ? request.x : 30f,
                        request.y != null ? request.y : 30f,
                        request.width  != null ? request.width  : 200f,
                        request.height != null ? request.height : 50f));
                appearance.setPageNumber(request.page != null ? request.page : 1);
                if (request.reason     != null) appearance.setReason(request.reason);
                if (request.location   != null) appearance.setLocation(request.location);
                if (request.contactInfo != null) appearance.setContact(request.contactInfo);
                // Text pur, fără iconița iText
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
                appearance.setLayer2Text(buildLayer2Text(request));
                log.info("prepare: câmp NOU creat la pozitia ({},{}) {}x{}",
                        request.x, request.y, request.width, request.height);
            } else {
                // Câmp EXISTENT pre-creat de Node la flow creation:
                // NU setăm rect — iText folosește rect-ul câmpului existent
                // NU setăm appearance — aspect minimal (doar semnatura electronică)
                // Rezultat: AcroForm Fields și Page Annots NU sunt modificate în incremental update
                PdfSignatureAppearance appearance = signer.getSignatureAppearance();
                if (request.reason      != null) appearance.setReason(request.reason);
                if (request.location    != null) appearance.setLocation(request.location);
                if (request.contactInfo != null) appearance.setContact(request.contactInfo);
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
                appearance.setLayer2Text(buildLayer2TextMinimal(request));
                log.info("prepare: câmp EXISTENT folosit — fara modificare AcroForm/Annots");
            }

            final byte[] signerCertDerFinal = signerCertDer;
            CapturingBlankContainer blank = new CapturingBlankContainer(
                    request.subFilter,
                    Boolean.TRUE.equals(request.useSignedAttributes),
                    signerCertDerFinal
            );
            // 65536 bytes: suficient pentru TSA token DigiCert (~6KB) + chain STS (~4KB)
            int estimatedSignatureSize = 65536;
            signer.signExternalContainer(blank, estimatedSignatureSize);

            byte[] preparedBytes = preparedOut.toByteArray();

            // ── DIAGNOSTIC: verificam ca bytes originali sunt INTACTI ──────────
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
                    log.error("DIAGNOSTIC CRITIC: bytes modificate la pozitia {} — sig anterioare INVALIDE!", firstDiff);
                }
            }
            log.info("prepare: OK — original={}b, prepared={}b, delta={}b, fieldName={}, hasCert={}",
                    pdfBytes.length, preparedBytes.length, preparedBytes.length - pdfBytes.length,
                    request.fieldName, signerCertDer != null);
            // ── END DIAGNOSTIC ─────────────────────────────────────────────────

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

    private String buildLayer2Text(PrepareRequest request, byte[] signerCertDer) {
        String role = normalize((request.signerRole == null || request.signerRole.isBlank())
                ? "SEMNATAR" : request.signerRole.toUpperCase());
        String function = normalize(request.signerFunction == null ? "" : request.signerFunction);
        String name = normalize(resolveDisplayName(request, signerCertDer));
        String dateStr = java.time.ZonedDateTime.now(java.time.ZoneId.of("Europe/Bucharest"))
                .format(java.time.format.DateTimeFormatter.ofPattern("dd.MM.yyyy, HH:mm"));

        StringBuilder sb = new StringBuilder();
        sb.append(role);
        if (!function.isBlank()) sb.append("\n").append(function);
        if (!name.isBlank()) sb.append("\n").append(name);
        sb.append("\n\nSemnat digital QES");
        sb.append("\n").append(dateStr);
        sb.append("\nDocFlowAI | STS Cloud QES");
        return sb.toString();
    }

    private String normalize(String s) {
        return s == null ? "" : s
                .replace("ă", "a").replace("â", "a").replace("î", "i")
                .replace("ș", "s").replace("ş", "s")
                .replace("ț", "t").replace("ţ", "t")
                .replace("Ă", "A").replace("Â", "A").replace("Î", "I")
                .replace("Ș", "S").replace("Ş", "S")
                .replace("Ț", "T").replace("Ţ", "T");
    }

    static class CapturingBlankContainer implements IExternalSignatureContainer {
        private final String subFilter;
        private final boolean useSignedAttributes;
        private final byte[] signingCertDer;
        byte[] documentDigest;
        String toBeSignedDigestBase64;

        CapturingBlankContainer(String subFilter, boolean useSignedAttributes, byte[] signingCertDer) {
            this.subFilter          = subFilter;
            this.useSignedAttributes = useSignedAttributes;
            this.signingCertDer     = signingCertDer;
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
