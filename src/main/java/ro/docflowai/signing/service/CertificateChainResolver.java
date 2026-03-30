package ro.docflowai.signing.service;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Service
public class CertificateChainResolver {

    private final HttpClient httpClient;
    private final boolean enabled;
    private final int maxDepth;

    public CertificateChainResolver(
            @Value("${trust.chain.fetch-enabled:true}") boolean enabled,
            @Value("${trust.chain.max-depth:3}") int maxDepth,
            @Value("${trust.chain.http-timeout-ms:5000}") int timeoutMs
    ) {
        this.enabled = enabled;
        this.maxDepth = maxDepth;
        this.httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofMillis(timeoutMs))
                .build();
    }

    public List<String> enrichChain(String leafPem, List<String> existingPemChain) {
        List<String> result = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();

        if (existingPemChain != null) {
            for (String pem : existingPemChain) {
                if (pem != null && !pem.isBlank()) {
                    String norm = normalizePem(pem);
                    if (seen.add(norm)) result.add(norm);
                }
            }
        }

        if (!enabled || leafPem == null || leafPem.isBlank()) {
            return result;
        }

        try {
            String currentPem = normalizePem(leafPem);
            for (int depth = 0; depth < maxDepth; depth++) {
                X509Certificate cert = parsePem(currentPem);
                if (isSelfSigned(cert)) {
                    break;
                }

                List<String> aiaUrls = extractCaIssuerUrls(currentPem);
                if (aiaUrls.isEmpty()) {
                    break;
                }

                String fetchedPem = null;
                for (String url : aiaUrls) {
                    fetchedPem = fetchCertificatePem(url);
                    if (fetchedPem != null && !fetchedPem.isBlank()) {
                        break;
                    }
                }

                if (fetchedPem == null || fetchedPem.isBlank()) {
                    break;
                }

                String normalizedFetched = normalizePem(fetchedPem);
                if (!seen.add(normalizedFetched)) {
                    break;
                }

                result.add(normalizedFetched);
                currentPem = normalizedFetched;
            }
        } catch (Exception ignored) {
            // Best effort only. We keep signing robust even when chain fetch fails.
        }

        return result;
    }

    private List<String> extractCaIssuerUrls(String pem) {
        List<String> urls = new ArrayList<>();
        try {
            X509CertificateHolder holder = new X509CertificateHolder(DerCmsSupport.pemToDer(pem));
            Extension ext = holder.getExtension(Extension.authorityInfoAccess);
            if (ext == null) return urls;

            ASN1OctetString oct = ext.getExtnValue();
            ASN1Primitive primitive = ASN1Primitive.fromByteArray(oct.getOctets());
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(primitive);
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (!AccessDescription.id_ad_caIssuers.equals(ad.getAccessMethod())) continue;
                GeneralName location = ad.getAccessLocation();
                if (location.getTagNo() != GeneralName.uniformResourceIdentifier) continue;
                String uri = ASN1IA5String.getInstance(location.getName()).getString();
                if (uri != null && (uri.startsWith("http://") || uri.startsWith("https://"))) {
                    urls.add(uri);
                }
            }
        } catch (Exception ignored) {
        }
        return urls;
    }

    private String fetchCertificatePem(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(10))
                    .header("Accept", "application/pkix-cert, application/x-x509-ca-cert, application/octet-stream, */*")
                    .build();
            HttpResponse<byte[]> res = httpClient.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (res.statusCode() < 200 || res.statusCode() >= 300 || res.body() == null || res.body().length == 0) {
                return null;
            }
            byte[] body = res.body();
            String asText = new String(body);
            if (asText.contains("BEGIN CERTIFICATE")) {
                return normalizePem(asText);
            }
            return derToPem(body);
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isSelfSigned(X509Certificate cert) {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    }

    private static X509Certificate parsePem(String pem) {
        try {
            byte[] der = DerCmsSupport.pemToDer(pem);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String derToPem(byte[] der) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }

    private static String normalizePem(String pem) {
        return derToPem(DerCmsSupport.pemToDer(pem));
    }
}
