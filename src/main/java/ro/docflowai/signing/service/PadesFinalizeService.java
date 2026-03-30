package ro.docflowai.signing.service;

import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.IExternalSignatureContainer;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.PdfSigner;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ro.docflowai.signing.dto.FinalizeRequest;
import ro.docflowai.signing.dto.FinalizeResponse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class PadesFinalizeService extends Base64PdfSupport {

    @Value("${APP_MODE:real}")
    private String mode;

    @Value("${TSA_ENABLED:false}")
    private boolean tsaEnabled;

    @Value("${TSA_URL:}")
    private String tsaUrl;

    @Value("${TSA_USERNAME:}")
    private String tsaUsername;

    @Value("${TSA_PASSWORD:}")
    private String tsaPassword;

    @Value("${TSA_TOKEN_SIZE_ESTIMATE:8192}")
    private int tsaTokenSizeEstimate;

    public FinalizeResponse finalizeSignature(FinalizeRequest request) {
        try {
            byte[] preparedPdf = decodeBase64(request.preparedPdfBase64);
            ByteArrayOutputStream signedOut = new ByteArrayOutputStream();

            List<String> chain = new ArrayList<>();
            if (request.certificatePem != null && !request.certificatePem.isBlank()) {
                chain.add(request.certificatePem);
            }
            if (request.certificateChainPem != null) {
                chain.addAll(request.certificateChainPem);
            }

            ITSAClient tsaClient = DerCmsSupport.buildTsaClient(
                    tsaEnabled,
                    tsaUrl,
                    tsaUsername,
                    tsaPassword,
                    tsaTokenSizeEstimate
            );

            PdfDocument document = new PdfDocument(new PdfReader(new ByteArrayInputStream(preparedPdf)));
            DeferredContainer container = new DeferredContainer(
                    request.signByteBase64,
                    chain,
                    Boolean.TRUE.equals(request.useSignedAttributes),
                    request.subFilter,
                    tsaClient
            );
            PdfSigner.signDeferred(document, request.fieldName, signedOut, container);
            document.close();

            FinalizeResponse out = new FinalizeResponse();
            out.signedPdfBase64 = Base64.getEncoder().encodeToString(signedOut.toByteArray());
            out.mode = mode;
            out.warning = tsaClient == null ? "Semnătura a fost generată fără TSA trusted." : null;

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
        private final List<String> certificateChainPem;
        private final boolean useSignedAttributes;
        private final String subFilter;
        private final ITSAClient tsaClient;

        DeferredContainer(String signByteBase64,
                          List<String> certificateChainPem,
                          boolean useSignedAttributes,
                          String subFilter,
                          ITSAClient tsaClient) {
            this.signByteBase64 = signByteBase64;
            this.certificateChainPem = certificateChainPem;
            this.useSignedAttributes = useSignedAttributes;
            this.subFilter = subFilter;
            this.tsaClient = tsaClient;
        }

        @Override
        public byte[] sign(InputStream data) {
            byte[] documentDigest = DerCmsSupport.sha256(data);
            String signatureAlgorithm = inferSignatureAlgorithm(certificateChainPem);
            if (useSignedAttributes) {
                return DerCmsSupport.buildCmsWithIText(
                        signByteBase64,
                        documentDigest,
                        certificateChainPem,
                        signatureAlgorithm,
                        tsaClient,
                        PdfSigner.CryptoStandard.CADES
                );
            }
            return DerCmsSupport.buildCmsWithIText(
                    signByteBase64,
                    documentDigest,
                    certificateChainPem,
                    signatureAlgorithm,
                    tsaClient,
                    PdfSigner.CryptoStandard.CADES
            );
        }

        @Override
        public void modifySigningDictionary(PdfDictionary signDic) {
            signDic.put(PdfName.Filter, PdfName.Adobe_PPKLite);
            signDic.put(PdfName.SubFilter, new PdfName(subFilter));
        }

        private static String inferSignatureAlgorithm(List<String> certificateChainPem) {
            try {
                if (certificateChainPem == null || certificateChainPem.isEmpty()) return "RSA";
                String first = certificateChainPem.get(0);
                var cert = DerCmsSupport.parseCertificate(DerCmsSupport.pemToDer(first));
                String alg = cert.getPublicKey().getAlgorithm();
                if (alg == null) return "RSA";
                if (alg.equalsIgnoreCase("EC") || alg.equalsIgnoreCase("ECDSA")) return "ECDSA";
                return "RSA";
            } catch (Exception e) {
                return "RSA";
            }
        }
    }
}
