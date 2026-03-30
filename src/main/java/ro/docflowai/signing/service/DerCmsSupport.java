package ro.docflowai.signing.service;

import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.TSAClientBouncyCastle;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

final class DerCmsSupport {
    private DerCmsSupport() {}

    static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (Exception e) {
            throw new RuntimeException("Nu am putut calcula SHA-256", e);
        }
    }

    static byte[] sha256(InputStream in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException("Nu am putut calcula SHA-256 din stream", e);
        }
    }

    static byte[] buildSignedAttrsDer(byte[] documentDigest) {
        try {
            ASN1EncodableVector attrs = new ASN1EncodableVector();
            attrs.add(new Attribute(
                    CMSAttributes.contentType,
                    new DERSet(CMSObjectIdentifiers.data)
            ));
            attrs.add(new Attribute(
                    CMSAttributes.messageDigest,
                    new DERSet(new DEROctetString(documentDigest))
            ));
            return new DERSet(attrs).getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            throw new RuntimeException("Nu am putut construi signedAttrs DER", e);
        }
    }

    static String calcSignedAttrsHashBase64(byte[] signedAttrsDerSet) {
        return Base64.getEncoder().encodeToString(sha256(signedAttrsDerSet));
    }

    static String calcPdfPkcs7SignedAttrsHashBase64(byte[] documentDigest,
                                                    List<String> certificateChainPem,
                                                    PdfSigner.CryptoStandard cryptoStandard) {
        try {
            X509Certificate[] chain = parseCertificateChain(certificateChainPem);
            PdfPKCS7 pkcs7 = new PdfPKCS7(null, chain, "SHA256", null, new BouncyCastleDigest(), false);
            byte[] attrs = pkcs7.getAuthenticatedAttributeBytes(documentDigest, cryptoStandard, null, null);
            return Base64.getEncoder().encodeToString(sha256(attrs));
        } catch (Exception e) {
            throw new RuntimeException("Nu am putut calcula hash-ul signedAttrs cu PdfPKCS7", e);
        }
    }

    static byte[] buildCmsWithIText(String signByteBase64,
                                    byte[] documentDigest,
                                    List<String> certificateChainPem,
                                    String signatureAlgorithm,
                                    ITSAClient tsaClient,
                                    PdfSigner.CryptoStandard cryptoStandard) {
        try {
            byte[] signatureBytes = Base64.getDecoder().decode(signByteBase64);
            X509Certificate[] chain = parseCertificateChain(certificateChainPem);
            PdfPKCS7 pkcs7 = new PdfPKCS7(null, chain, "SHA256", null, new BouncyCastleDigest(), false);
            pkcs7.setExternalSignatureValue(signatureBytes, null, signatureAlgorithm);
            Collection<byte[]> ocsp = null;
            Collection<byte[]> crls = null;
            return pkcs7.getEncodedPKCS7(documentDigest, cryptoStandard, tsaClient, ocsp, crls);
        } catch (Exception e) {
            throw new RuntimeException("Nu am putut construi CMS/PKCS#7 cu iText", e);
        }
    }

    static ITSAClient buildTsaClient(boolean enabled,
                                     String url,
                                     String username,
                                     String password,
                                     int tokenSizeEstimate) {
        if (!enabled || url == null || url.isBlank()) {
            return null;
        }
        try {
            return new TSAClientBouncyCastle(url, blankToNull(username), blankToNull(password), tokenSizeEstimate, "SHA-256");
        } catch (Exception e) {
            throw new RuntimeException("Nu am putut crea TSA client", e);
        }
    }

    static X509Certificate[] parseCertificateChain(List<String> certificateChainPem) {
        try {
            List<X509Certificate> chain = new ArrayList<>();
            if (certificateChainPem != null) {
                for (String pem : certificateChainPem) {
                    if (pem == null || pem.isBlank()) continue;
                    X509Certificate cert = parseCertificate(pemToDer(pem));
                    boolean duplicate = false;
                    for (X509Certificate existing : chain) {
                        if (java.util.Arrays.equals(existing.getEncoded(), cert.getEncoded())) {
                            duplicate = true;
                            break;
                        }
                    }
                    if (!duplicate) {
                        chain.add(cert);
                    }
                }
            }
            return chain.toArray(new X509Certificate[0]);
        } catch (Exception e) {
            throw new RuntimeException("Nu am putut interpreta lanțul de certificate", e);
        }
    }

    static X509Certificate parseCertificate(byte[] der) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new RuntimeException("Certificatul X.509 nu a putut fi interpretat", e);
        }
    }

    static byte[] pemToDer(String pem) {
        String body = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(body);
    }

    private static String blankToNull(String v) {
        return v == null || v.isBlank() ? null : v;
    }
}
