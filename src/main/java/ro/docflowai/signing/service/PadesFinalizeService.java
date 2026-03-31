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

@Service
public class PadesFinalizeService extends Base64PdfSupport {

    private static final Logger log = LoggerFactory.getLogger(PadesFinalizeService.class);

    @Value("${APP_MODE:real}")
    private String mode;

    private final CertificateChainResolver certificateChainResolver;

    public PadesFinalizeService(CertificateChainResolver certificateChainResolver) {
        this.certificateChainResolver = certificateChainResolver;
    }

    public FinalizeResponse finalizeSignature(FinalizeRequest request) {
        try {
            // LOG DIAGNOSTIC: afisam info despre signByte primit de la STS
            if (request.signByteBase64 != null) {
                byte[] rawSig = Base64.getDecoder().decode(request.signByteBase64);
                log.info("finalizeSignature: signByte primit de la STS: len={}, firstByte=0x{}, fieldName={}",
                        rawSig.length,
                        rawSig.length > 0 ? String.format("%02x", rawSig[0] & 0xFF) : "??",
                        request.fieldName);
                // Interpretare: len=64 + firstByte!=0x30 => ECDSA raw r||s (fix aplicat in DerCmsSupport)
                //               len=64 + firstByte==0x30 => ECDSA DER deja (no-op)
                //               len=256 sau 512           => RSA (no-op)
                if (rawSig.length == 64 && (rawSig[0] & 0xFF) != 0x30) {
                    log.info("finalizeSignature: ECDSA raw r||s confirmat — conversie DER va fi aplicata");
                } else if (rawSig.length == 64) {
                    log.info("finalizeSignature: ECDSA bytes par DER deja (firstByte=0x30)");
                } else {
                    log.info("finalizeSignature: RSA sau format extins (len={})", rawSig.length);
                }
            }

            byte[] preparedPdf = decodeBase64(request.preparedPdfBase64);
            ByteArrayOutputStream signedOut = new ByteArrayOutputStream();

            PdfDocument document = new PdfDocument(new PdfReader(new ByteArrayInputStream(preparedPdf)));
            java.util.List<String> enrichedChain = certificateChainResolver.enrichChain(
                    request.certificatePem,
                    request.certificateChainPem
            );
            log.info("finalizeSignature: lanț certificate enriched: {} certificate(s)", enrichedChain.size());

            DeferredContainer container = new DeferredContainer(
                    request.signByteBase64,
                    request.certificatePem,
                    enrichedChain,
                    Boolean.TRUE.equals(request.useSignedAttributes),
                    request.subFilter
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

            log.info("finalizeSignature: PDF semnat generat cu succes (size={} bytes)", signedOut.size());
            return out;

        } catch (Exception e) {
            log.error("finalizeSignature: EROARE — {}", e.getMessage(), e);
            throw new RuntimeException("finalize PAdES a esuat", e);
        }
    }

    static class DeferredContainer implements IExternalSignatureContainer {
        private final String signByteBase64;
        private final String certificatePem;
        private final java.util.List<String> certificateChainPem;
        private final boolean useSignedAttributes;
        private final String subFilter;

        DeferredContainer(String signByteBase64,
                          String certificatePem,
                          java.util.List<String> certificateChainPem,
                          boolean useSignedAttributes,
                          String subFilter) {
            this.signByteBase64 = signByteBase64;
            this.certificatePem = certificatePem;
            this.certificateChainPem = certificateChainPem;
            this.useSignedAttributes = useSignedAttributes;
            this.subFilter = subFilter;
        }

        @Override
        public byte[] sign(InputStream data) {
            byte[] documentDigest = DerCmsSupport.sha256(data);
            byte[] signedAttrs = useSignedAttributes ? DerCmsSupport.buildSignedAttrsDer(documentDigest) : null;
            return DerCmsSupport.buildCmsFromRawSignature(signByteBase64, certificatePem, certificateChainPem, signedAttrs);
        }

        @Override
        public void modifySigningDictionary(PdfDictionary signDic) {
            signDic.put(PdfName.Filter, PdfName.Adobe_PPKLite);
            signDic.put(PdfName.SubFilter, new PdfName(subFilter));
        }
    }
}
