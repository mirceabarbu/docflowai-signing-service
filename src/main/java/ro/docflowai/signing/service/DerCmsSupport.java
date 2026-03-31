package ro.docflowai.signing.service;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

final class DerCmsSupport {

    private static final Logger log = LoggerFactory.getLogger(DerCmsSupport.class);

    private DerCmsSupport() {}

    static final String OID_SHA256        = "2.16.840.1.101.3.4.2.1";
    static final String OID_RSA           = "1.2.840.113549.1.1.1";
    static final String OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
    static final String OID_ECDSA_SHA256  = "1.2.840.10045.4.3.2";

    // ── Hash helpers ──────────────────────────────────────────────────────────

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException("Nu am putut calcula SHA-256", e);
        }
    }

    static byte[] sha256(InputStream in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException("Nu am putut calcula SHA-256 din stream", e);
        }
    }

    static String calcSignedAttrsHashBase64(byte[] signedAttrsDerSet) {
        return Base64.getEncoder().encodeToString(sha256(signedAttrsDerSet));
    }

    // ── SignedAttrs DER builder ───────────────────────────────────────────────

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

    // ── ECDSA raw r||s → DER SEQUENCE converter ───────────────────────────────
    //
    // STS returneaza signByte ca byte[] raw pentru ECDSA P-256:
    //   bytes[ 0..31] = r  (big-endian unsigned, 32 bytes)
    //   bytes[32..63] = s  (big-endian unsigned, 32 bytes)
    //
    // CMS / RFC 3279 cere DER SEQUENCE { INTEGER r, INTEGER s }.
    // Fara aceasta conversie semnatura este criptografic invalida in Adobe/DSS.
    //
    // Detectam formatul raw: lungime == 64 SI primul byte != 0x30 (tag SEQUENCE DER).
    // Daca STS returneaza vreodata DER direct, metoda este no-op.

    static byte[] normalizeEcdsaSignature(X509CertificateHolder leafHolder, byte[] signatureBytes) {
        String pkAlg = leafHolder.getSubjectPublicKeyInfo()
                .getAlgorithm().getAlgorithm().getId();

        // RSA: bytes-urile sunt direct valoarea semnaturii, fara conversie necesara
        if (!OID_EC_PUBLIC_KEY.equals(pkAlg)) {
            log.debug("normalizeEcdsaSignature: RSA, fara conversie (len={})", signatureBytes.length);
            return signatureBytes;
        }

        // ECDSA: detectam raw r||s (64 bytes, fara tag DER 0x30)
        if (signatureBytes.length == 64 && (signatureBytes[0] & 0xFF) != 0x30) {
            log.info("normalizeEcdsaSignature: ECDSA raw r||s detectat (len=64, firstByte=0x{}) -> DER SEQUENCE",
                    String.format("%02x", signatureBytes[0] & 0xFF));
            try {
                byte[] r = Arrays.copyOfRange(signatureBytes, 0, 32);
                byte[] s = Arrays.copyOfRange(signatureBytes, 32, 64);
                ASN1EncodableVector seq = new ASN1EncodableVector();
                // BigInteger(1, bytes) = interpretare unsigned (MSB=1 nu inseamna negativ)
                seq.add(new ASN1Integer(new BigInteger(1, r)));
                seq.add(new ASN1Integer(new BigInteger(1, s)));
                byte[] derSig = new DERSequence(seq).getEncoded(ASN1Encoding.DER);
                log.info("normalizeEcdsaSignature: DER SEQUENCE generat cu succes (len={})", derSig.length);
                return derSig;
            } catch (Exception e) {
                log.warn("normalizeEcdsaSignature: conversie esuata, folosim bytes originali", e);
                return signatureBytes;
            }
        }

        // Deja DER (primul byte = 0x30) sau alta lungime neasteptata (ex. P-384 = 96 bytes)
        log.info("normalizeEcdsaSignature: ECDSA bytes par a fi deja DER sau format extins (len={}, firstByte=0x{})",
                signatureBytes.length, String.format("%02x", signatureBytes[0] & 0xFF));
        return signatureBytes;
    }

    // ── CMS builder ───────────────────────────────────────────────────────────

    static byte[] buildCmsFromRawSignature(String signByteBase64,
                                           String certPem,
                                           List<String> chainPem,
                                           byte[] signedAttrsDerSet) {
        try {
            byte[] signatureBytes = Base64.getDecoder().decode(signByteBase64);

            // LOG DIAGNOSTIC — vizibil in Railway logs la primul test
            log.info("buildCmsFromRawSignature: signByte len={}, firstByte=0x{}",
                    signatureBytes.length,
                    signatureBytes.length > 0 ? String.format("%02x", signatureBytes[0] & 0xFF) : "??");

            X509CertificateHolder leafHolder = new X509CertificateHolder(pemToDer(certPem));

            // FIX PRINCIPAL: raw ECDSA r||s → DER SEQUENCE
            signatureBytes = normalizeEcdsaSignature(leafHolder, signatureBytes);

            // Construim lantul de certificate (deduplicat)
            List<X509CertificateHolder> chain = new ArrayList<>();
            chain.add(leafHolder);

            if (chainPem != null) {
                for (String pem : chainPem) {
                    if (pem == null || pem.isBlank()) continue;
                    X509CertificateHolder holder = new X509CertificateHolder(pemToDer(pem));
                    boolean duplicate = false;
                    for (X509CertificateHolder existing : chain) {
                        try {
                            if (Arrays.equals(existing.getEncoded(), holder.getEncoded())) {
                                duplicate = true;
                                break;
                            }
                        } catch (Exception ex) {
                            throw new RuntimeException("Nu am putut compara certificatele din lant", ex);
                        }
                    }
                    if (!duplicate) chain.add(holder);
                }
            }

            AlgorithmIdentifier digestAlg =
                    new DefaultDigestAlgorithmIdentifierFinder().find(new ASN1ObjectIdentifier(OID_SHA256));
            AlgorithmIdentifier sigAlg = signatureAlgorithmFor(leafHolder);

            SignerIdentifier sid = new SignerIdentifier(new IssuerAndSerialNumber(
                    leafHolder.getIssuer(),
                    leafHolder.getSerialNumber()
            ));

            ASN1Set signedAttrs = signedAttrsDerSet != null
                    ? ASN1Set.getInstance(ASN1Primitive.fromByteArray(signedAttrsDerSet))
                    : null;

            SignerInfo signerInfo = new SignerInfo(
                    sid,
                    digestAlg,
                    signedAttrs,
                    sigAlg,
                    new DEROctetString(signatureBytes),
                    null
            );

            ASN1EncodableVector certVector = new ASN1EncodableVector();
            for (X509CertificateHolder holder : chain) certVector.add(holder.toASN1Structure());

            ASN1EncodableVector signerInfos = new ASN1EncodableVector();
            signerInfos.add(signerInfo);

            SignedData signedData = new SignedData(
                    new DERSet(digestAlg),
                    new ContentInfo(CMSObjectIdentifiers.data, null),
                    new DERSet(certVector),
                    null,
                    new DERSet(signerInfos)
            );

            ContentInfo cms = new ContentInfo(CMSObjectIdentifiers.signedData, signedData);
            byte[] encoded = cms.getEncoded(ASN1Encoding.DER);
            log.info("buildCmsFromRawSignature: CMS final generat (len={})", encoded.length);
            return encoded;

        } catch (Exception e) {
            throw new RuntimeException("Nu am putut construi CMS din signByte", e);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static AlgorithmIdentifier signatureAlgorithmFor(X509CertificateHolder holder) {
        String pkAlg = holder.getSubjectPublicKeyInfo()
                .getAlgorithm().getAlgorithm().getId();
        if (OID_EC_PUBLIC_KEY.equals(pkAlg)) {
            return new AlgorithmIdentifier(new ASN1ObjectIdentifier(OID_ECDSA_SHA256));
        }
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier(OID_RSA), DERNull.INSTANCE);
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
}
