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
import java.util.Base64;

@Service
public class PadesPrepareService extends Base64PdfSupport {

    private static final Logger log = LoggerFactory.getLogger(PadesPrepareService.class);

    @Value("${APP_MODE:real}")
    private String mode;

    public PrepareResponse prepare(PrepareRequest request) {
        try {
            // b236: dacă certificatul semnatarului e furnizat, îl includem în signedAttrs
            // (signing-certificate-v2 per RFC 5035 / PAdES-B-B)
            byte[] signerCertDer = null;
            if (request.signerCertificatePem != null && !request.signerCertificatePem.isBlank()) {
                signerCertDer = DerCmsSupport.pemToDer(request.signerCertificatePem);
                log.info("prepare: signerCertificatePem primit — signing-certificate-v2 va fi inclus in signedAttrs");
            } else {
                log.warn("prepare: signerCertificatePem absent — signedAttrs fara signing-certificate-v2 (DSS warning)");
            }

            byte[] pdfBytes = decodeBase64(request.pdfBase64);
            ByteArrayOutputStream preparedOut = new ByteArrayOutputStream();
            PdfReader reader = new PdfReader(new ByteArrayInputStream(pdfBytes));
            PdfSigner signer = new PdfSigner(reader, preparedOut, new StampingProperties().useAppendMode());
            signer.setFieldName(request.fieldName);

            PdfSignatureAppearance appearance = signer.getSignatureAppearance();
            appearance.setPageRect(new Rectangle(request.x, request.y, request.width, request.height));
            appearance.setPageNumber(request.page);
            if (request.reason != null) appearance.setReason(request.reason);
            if (request.location != null) appearance.setLocation(request.location);
            if (request.contactInfo != null) appearance.setContact(request.contactInfo);
            appearance.setLayer2Text(buildLayer2Text(request));

            final byte[] signerCertDerFinal = signerCertDer;
            CapturingBlankContainer blank = new CapturingBlankContainer(
                    request.subFilter,
                    Boolean.TRUE.equals(request.useSignedAttributes),
                    signerCertDerFinal
            );
            int estimatedSignatureSize = 32768;
            signer.signExternalContainer(blank, estimatedSignatureSize);

            PrepareResponse out = new PrepareResponse();
            out.preparedPdfBase64 = Base64.getEncoder().encodeToString(preparedOut.toByteArray());
            out.documentDigestBase64 = Base64.getEncoder().encodeToString(blank.documentDigest);
            out.toBeSignedDigestBase64 = blank.toBeSignedDigestBase64;
            out.fieldName = request.fieldName;
            out.usesSignedAttributes = request.useSignedAttributes;
            out.subFilter = request.subFilter;
            out.estimatedSignatureSize = estimatedSignatureSize;
            out.mode = mode;
            out.warning = signerCertDer == null
                    ? "signerCertificatePem absent — signing-certificate-v2 nu e inclus in signedAttrs"
                    : null;

            log.info("prepare: OK — fieldName={}, hasCert={}, toBeSignedDigestLen={}",
                    request.fieldName, signerCertDer != null, out.toBeSignedDigestBase64.length());
            return out;
        } catch (Exception e) {
            log.error("prepare: EROARE — {}", e.getMessage(), e);
            throw new RuntimeException("prepare PAdES a esuat", e);
        }
    }

    private String buildLayer2Text(PrepareRequest request) {
        String role = request.signerRole == null || request.signerRole.isBlank()
                ? "Semnatar" : request.signerRole;
        return "Semnat digital QES\n" + request.signerName + "\n" + role;
    }

    static class CapturingBlankContainer implements IExternalSignatureContainer {
        private final String subFilter;
        private final boolean useSignedAttributes;
        private final byte[] signingCertDer; // pentru signing-certificate-v2
        byte[] documentDigest;
        String toBeSignedDigestBase64;

        CapturingBlankContainer(String subFilter, boolean useSignedAttributes, byte[] signingCertDer) {
            this.subFilter = subFilter;
            this.useSignedAttributes = useSignedAttributes;
            this.signingCertDer = signingCertDer;
        }

        @Override
        public byte[] sign(InputStream data) {
            documentDigest = DerCmsSupport.sha256(data);
            if (useSignedAttributes) {
                // Construim signedAttrs cu signing-certificate-v2 dacă avem cert
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
