package ro.docflowai.signing.service;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfFormField;
import com.itextpdf.kernel.pdf.PdfArray;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ro.docflowai.signing.dto.FinalizeRequest;
import ro.docflowai.signing.dto.FinalizeResponse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * PadesFinalizeService b237
 *
 * Abordare MANUAL EMBEDDING (nu mai folosim PdfSigner.signDeferred):
 *
 * signDeferred re-procesează intern PDF-ul și poate modifica bytes
 * din revision-urile anterioare, corupând semnăturile existente
 * în fluxuri cu 2+ semnatari.
 *
 * Soluție (identică cu @signpdf în Node.js):
 *   1. Citim ByteRange din câmpul de semnătură al PDF-ului pregătit
 *   2. Concatenăm cei doi segmenți ByteRange → conținut de semnat
 *   3. Construim CMS din conținut + signByte STS
 *   4. Înlocuim placeholder-ul hex din PDF byte-for-byte
 *      (NUMAI bytes-urile placeholder se schimbă — tot restul identic)
 *
 * Aceasta garantează că semnăturile anterioare rămân VALIDE.
 */
@Service
public class PadesFinalizeService extends Base64PdfSupport {

    private static final Logger log = LoggerFactory.getLogger(PadesFinalizeService.class);

    @Value("${APP_MODE:real}")
    private String mode;

    @Value("${tsa.url:http://timestamp.digicert.com}")
    private String defaultTsaUrl;

    private final CertificateChainResolver certificateChainResolver;

    public PadesFinalizeService(CertificateChainResolver certificateChainResolver) {
        this.certificateChainResolver = certificateChainResolver;
    }

    public FinalizeResponse finalizeSignature(FinalizeRequest request) {
        try {
            // ── LOG DIAGNOSTIC ────────────────────────────────────────────────
            if (request.signByteBase64 != null) {
                byte[] rawSig = Base64.getDecoder().decode(request.signByteBase64);
                log.info("finalizeSignature: signByte len={}, firstByte=0x{}, fieldName={}",
                        rawSig.length,
                        rawSig.length > 0 ? String.format("%02x", rawSig[0] & 0xFF) : "??",
                        request.fieldName);
            }

            byte[] preparedPdfBytes = decodeBase64(request.preparedPdfBase64);
            log.info("finalizeSignature: prepared PDF size={} bytes", preparedPdfBytes.length);

            // ── PASUL 1: Citim ByteRange din PDF pregătit ─────────────────────
            long[] byteRange = readByteRange(preparedPdfBytes, request.fieldName);
            log.info("finalizeSignature: ByteRange=[{}, {}, {}, {}]",
                    byteRange[0], byteRange[1], byteRange[2], byteRange[3]);

            // ── PASUL 2: Construim conținutul de semnat (cei doi segmenți) ────
            byte[] contentToSign = buildByteRangeContent(preparedPdfBytes, byteRange);
            log.info("finalizeSignature: contentToSign size={} bytes", contentToSign.length);

            // ── PASUL 3: Construim CMS (consistent cu prepare) ────────────────
            byte[] documentDigest = DerCmsSupport.sha256(contentToSign);

            // Reconstruim signedAttrs IDENTIC cu cele din prepare
            // (același cert → același signing-certificate-v2 → același hash trimis la STS)
            byte[] signerCertDer = null;
            try {
                signerCertDer = DerCmsSupport.pemToDer(request.certificatePem);
            } catch (Exception e) {
                log.warn("finalizeSignature: nu am putut decoda cert PEM: {}", e.getMessage());
            }

            byte[] signedAttrs = Boolean.TRUE.equals(request.useSignedAttributes)
                    ? DerCmsSupport.buildSignedAttrsDer(documentDigest, signerCertDer)
                    : null;

            List<String> enrichedChain = certificateChainResolver.enrichChain(
                    request.certificatePem, request.certificateChainPem);
            log.info("finalizeSignature: chain enriched: {} cert(s)", enrichedChain.size());

            String tsaUrl = (request.tsaUrl != null && !request.tsaUrl.isBlank())
                    ? request.tsaUrl : defaultTsaUrl;

            byte[] cmsBytes = DerCmsSupport.buildCmsFromRawSignature(
                    request.signByteBase64, request.certificatePem,
                    enrichedChain, signedAttrs, tsaUrl);
            log.info("finalizeSignature: CMS construit ({} bytes)", cmsBytes.length);

            // ── PASUL 4: Embedding manual — NUMAI placeholder-ul se schimbă ──
            byte[] signedPdfBytes = embedCmsInPdf(preparedPdfBytes, byteRange, cmsBytes);
            log.info("finalizeSignature: PDF semnat generat ({} bytes)", signedPdfBytes.length);

            String signedPdfBase64 = Base64.getEncoder().encodeToString(signedPdfBytes);

            FinalizeResponse out = new FinalizeResponse();
            out.signedPdfBase64 = signedPdfBase64;
            out.mode = mode;
            out.warning = null;

            FinalizeResponse.Validation validation = new FinalizeResponse.Validation();
            validation.byteRangeOk = true;
            validation.signatureEmbedded = true;
            validation.fieldName = request.fieldName;
            out.validation = validation;

            return out;

        } catch (Exception e) {
            log.error("finalizeSignature: EROARE — {}", e.getMessage(), e);
            throw new RuntimeException("finalize PAdES a esuat", e);
        }
    }

    // ── Citire ByteRange din câmpul de semnătură ──────────────────────────────

    private long[] readByteRange(byte[] pdfBytes, String fieldName) throws Exception {
        PdfReader reader = new PdfReader(new ByteArrayInputStream(pdfBytes));
        PdfDocument doc = new PdfDocument(reader);
        try {
            PdfAcroForm acroForm = PdfAcroForm.getAcroForm(doc, false);
            if (acroForm == null) throw new RuntimeException("AcroForm negăsit în PDF");

            PdfFormField field = acroForm.getField(fieldName);
            if (field == null) throw new RuntimeException("Câmpul de semnătură '" + fieldName + "' nu există în PDF");

            PdfDictionary sigValue = (PdfDictionary) field.getValue();
            if (sigValue == null) throw new RuntimeException("Valoarea câmpului '" + fieldName + "' e null");

            PdfArray br = sigValue.getAsArray(PdfName.ByteRange);
            if (br == null || br.size() < 4)
                throw new RuntimeException("ByteRange invalid sau absent în câmpul '" + fieldName + "'");

            long[] result = new long[] {
                    br.getAsNumber(0).longValue(),
                    br.getAsNumber(1).longValue(),
                    br.getAsNumber(2).longValue(),
                    br.getAsNumber(3).longValue()
            };
            log.debug("readByteRange: field={} → [{}, {}, {}, {}]",
                    fieldName, result[0], result[1], result[2], result[3]);
            return result;
        } finally {
            doc.close();
        }
    }

    // ── Construire conținut de semnat din ByteRange ───────────────────────────
    // ByteRange = [start1, len1, start2, len2]
    // Conținut = bytes[start1..start1+len1] + bytes[start2..start2+len2]

    private byte[] buildByteRangeContent(byte[] pdfBytes, long[] br) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(pdfBytes, (int) br[0], (int) br[1]);
        bos.write(pdfBytes, (int) br[2], (int) br[3]);
        return bos.toByteArray();
    }

    // ── Embedding manual al CMS în placeholder ────────────────────────────────
    //
    // Structura în PDF pregătit:
    //   /Contents <0000...0000>
    //              ^          ^
    //           br[1]     br[2]-1
    //
    // br[1]       = poziția byte-ului '<'
    // br[1]+1     = primul char hex
    // br[2]-2     = ultimul char hex (inclusiv)
    // br[2]-1     = poziția byte-ului '>'
    //
    // hexMaxLen = br[2] - br[1] - 2  (lungimea zonei hex între < și >)
    //
    // Operație: înlocuim zona hex cu CMS-hex padded cu '0'
    // NUMAI acele bytes se schimbă — tot restul PDF-ului rămâne IDENTIC.

    private byte[] embedCmsInPdf(byte[] preparedPdfBytes, long[] br, byte[] cmsBytes) {
        int hexStart = (int) br[1] + 1;
        int hexMaxLen = (int) (br[2] - br[1] - 2);

        // Convertim CMS în hex uppercase
        String cmsHex = new String(Hex.encode(cmsBytes)).toUpperCase();

        if (cmsHex.length() > hexMaxLen) {
            throw new RuntimeException(
                    "CMS hex length " + cmsHex.length() +
                    " depășește placeholder-ul de " + hexMaxLen + " caractere. " +
                    "Mărește estimatedSignatureSize în PadesPrepareService.");
        }

        log.info("embedCmsInPdf: cmsHex.len={}, placeholder.len={}, utilizare={}%",
                cmsHex.length(), hexMaxLen,
                String.format("%.1f", cmsHex.length() * 100.0 / hexMaxLen));

        // Construim zona hex cu padding de '0'
        StringBuilder padded = new StringBuilder(hexMaxLen);
        padded.append(cmsHex);
        while (padded.length() < hexMaxLen) padded.append('0');

        // Clonăm PDF-ul și înlocuim exact zona placeholder
        byte[] signedPdfBytes = Arrays.copyOf(preparedPdfBytes, preparedPdfBytes.length);
        byte[] hexBytes = padded.toString().getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(hexBytes, 0, signedPdfBytes, hexStart, hexBytes.length);

        return signedPdfBytes;
    }
}
