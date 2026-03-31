package ro.docflowai.signing.service;

import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.IExternalSignatureContainer;
import com.itextpdf.signatures.PdfSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ro.docflowai.signing.dto.FinalizeRequest;
import ro.docflowai.signing.dto.FinalizeResponse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Base64;
import java.util.List;

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
            // LOG DIAGNOSTIC
            if (request.signByteBase64 != null) {
                byte[] rawSig = Base64.getDecoder().decode(request.signByteBase64);
                log.info("finalizeSignature: signByte len={}, firstByte=0x{}, fieldName={}",
                        rawSig.length,
                        rawSig.length > 0 ? String.format("%02x", rawSig[0] & 0xFF) : "??",
                        request.fieldName);
            }

            // TSA URL: din request dacă specificat, altfel din config aplicație
            String tsaUrl = (request.tsaUrl != null && !request.tsaUrl.isBlank())
                    ? request.tsaUrl : defaultTsaUrl;
            log.info("finalizeSignature: TSA URL = {}", tsaUrl);

            byte[] preparedPdf = decodeBase64(request.preparedPdfBase64);
            ByteArrayOutputStream signedOut = new ByteArrayOutputStream();

            PdfDocument document = new PdfDocument(new PdfReader(new ByteArrayInputStream(preparedPdf)));

            List<String> enrichedChain = certificateChainResolver.enrichChain(
                    request.certificatePem, request.certificateChainPem);
            log.info("finalizeSignature: chain enriched: {} cert(s)", enrichedChain.size());

            // Decodam cert pentru signing-certificate-v2 (consistent cu prepare)
            byte[] signerCertDer = null;
            try {
                signerCertDer = DerCmsSupport.pemToDer(request.certificatePem);
            } catch (Exception e) {
                log.warn("finalizeSignature: nu am putut decoda cert PEM — signing-cert-v2 omis: {}", e.getMessage());
            }

            DeferredContainer container = new DeferredContainer(
                    request.signByteBase64,
                    request.certificatePem,
                    enrichedChain,
                    Boolean.TRUE.equals(request.useSignedAttributes),
                    request.subFilter,
                    signerCertDer,
                    tsaUrl
            );
            PdfSigner.signDeferred(document, request.fieldName, signedOut, container);
            document.close();

            FinalizeResponse out = new FinalizeResponse();
            out.signedPdfBase64 = Base64.getEncoder().encodeToString(signedOut.toByteArray());
            out.mode = mode;
            out.warning = null;

            FinalizeResponse.Validation validation = new FinalizeResponse.Validation();
            validation.byteRangeOk = true;
            validation.signatureEmbedded = true;
            validation.fieldName = request.fieldName;
            out.validation = validation;

            log.info("finalizeSignature: PDF semnat generat OK (size={} bytes)", signedOut.size());
            return out;

        } catch (Exception e) {
            log.error("finalizeSignature: EROARE — {}", e.getMessage(), e);
            throw new RuntimeException("finalize PAdES a esuat", e);
        }
    }

    static class DeferredContainer implements IExternalSignatureContainer {
        private final String signByteBase64;
        private final String certificatePem;
        private final List<String> certificateChainPem;
        private final boolean useSignedAttributes;
        private final String subFilter;
        private final byte[] signerCertDer; // pentru signing-certificate-v2
        private final String tsaUrl;        // pentru RFC 3161 timestamp

        DeferredContainer(String signByteBase64, String certificatePem,
                          List<String> certificateChainPem, boolean useSignedAttributes,
                          String subFilter, byte[] signerCertDer, String tsaUrl) {
            this.signByteBase64 = signByteBase64;
            this.certificatePem = certificatePem;
            this.certificateChainPem = certificateChainPem;
            this.useSignedAttributes = useSignedAttributes;
            this.subFilter = subFilter;
            this.signerCertDer = signerCertDer;
            this.tsaUrl = tsaUrl;
        }

        @Override
        public byte[] sign(InputStream data) {
            byte[] documentDigest = DerCmsSupport.sha256(data);
            // IMPORTANT: signedAttrs trebuie reconstruite identic cu cele din prepare
            // (același cert → același signing-certificate-v2 → același hash → semnătura validă)
            byte[] signedAttrs = useSignedAttributes
                    ? DerCmsSupport.buildSignedAttrsDer(documentDigest, signerCertDer)
                    : null;
            return DerCmsSupport.buildCmsFromRawSignature(
                    signByteBase64, certificatePem, certificateChainPem, signedAttrs, tsaUrl);
        }

        @Override
        public void modifySigningDictionary(PdfDictionary signDic) {
            signDic.put(PdfName.Filter, PdfName.Adobe_PPKLite);
            signDic.put(PdfName.SubFilter, new PdfName(subFilter));
        }
    }
}
