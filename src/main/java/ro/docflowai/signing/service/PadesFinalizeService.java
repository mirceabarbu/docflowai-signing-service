package ro.docflowai.signing.service;

import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.IExternalSignatureContainer;
import com.itextpdf.signatures.PdfSigner;
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

    @Value("${APP_MODE:real}")
    private String mode;

    public FinalizeResponse finalizeSignature(FinalizeRequest request) {
        try {
            byte[] preparedPdf = decodeBase64(request.preparedPdfBase64);
            ByteArrayOutputStream signedOut = new ByteArrayOutputStream();

            PdfDocument document = new PdfDocument(new PdfReader(new ByteArrayInputStream(preparedPdf)));
            DeferredContainer container = new DeferredContainer(
                    request.signByteBase64,
                    request.certificatePem,
                    request.certificateChainPem,
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
            return out;
        } catch (Exception e) {
            throw new RuntimeException("finalize PAdES a eșuat", e);
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
            byte[] signedAttrs = useSignedAttributes ? DerCmsSupport.buildSignedAttrsImplicit(documentDigest) : null;
            return DerCmsSupport.buildCmsFromRawSignature(signByteBase64, certificatePem, certificateChainPem, signedAttrs);
        }

        @Override
        public void modifySigningDictionary(PdfDictionary signDic) {
            signDic.put(PdfName.Filter, PdfName.Adobe_PPKLite);
            signDic.put(PdfName.SubFilter, new PdfName(subFilter));
        }
    }
}
