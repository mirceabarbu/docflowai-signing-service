package ro.docflowai.signing.service;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.tsp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

final class DerCmsSupport {

    private static final Logger log = LoggerFactory.getLogger(DerCmsSupport.class);

    private DerCmsSupport() {}

    static final String OID_SHA256            = "2.16.840.1.101.3.4.2.1";
    static final String OID_RSA               = "1.2.840.113549.1.1.1";
    static final String OID_EC_PUBLIC_KEY     = "1.2.840.10045.2.1";
    static final String OID_ECDSA_SHA256      = "1.2.840.10045.4.3.2";
    // id-aa-signingCertificateV2 (RFC 5035)
    static final String OID_SIGNING_CERT_V2   = "1.2.840.113549.1.9.16.2.47";
    // id-aa-signatureTimeStampToken (RFC 3161)
    static final String OID_SIGNATURE_TST     = "1.2.840.113549.1.9.16.2.14";

    // ── Hash helpers ──────────────────────────────────────────────────────────

    static byte[] sha256(byte[] data) {
        try { return MessageDigest.getInstance("SHA-256").digest(data); }
        catch (Exception e) { throw new RuntimeException("SHA-256 failed", e); }
    }

    static byte[] sha256(InputStream in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192]; int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
            return md.digest();
        } catch (Exception e) { throw new RuntimeException("SHA-256 stream failed", e); }
    }

    static String calcSignedAttrsHashBase64(byte[] signedAttrsDerSet) {
        return Base64.getEncoder().encodeToString(sha256(signedAttrsDerSet));
    }

    // ── SignedAttrs DER builder ───────────────────────────────────────────────
    //
    // Când signingCertDer != null, adaugă atributul id-aa-signingCertificateV2 (RFC 5035).
    // Acesta leagă criptografic certificatul de signedAttrs și e obligatoriu în PAdES-B-B.
    // IMPORTANT: hash-ul primit de STS trebuie calculat din signedAttrs care conțin acest atribut,
    //            deci certificatul trebuie cunoscut ÎNAINTE de a calcula hash-ul → fluxul b236.

    static byte[] buildSignedAttrsDer(byte[] documentDigest, byte[] signingCertDer) {
        try {
            ASN1EncodableVector attrs = new ASN1EncodableVector();

            // 1. contentType
            attrs.add(new Attribute(CMSAttributes.contentType, new DERSet(CMSObjectIdentifiers.data)));

            // 2. messageDigest
            attrs.add(new Attribute(CMSAttributes.messageDigest,
                    new DERSet(new DEROctetString(documentDigest))));

            // 3. signing-certificate-v2 (când certificatul e cunoscut)
            if (signingCertDer != null) {
                byte[] certHash = sha256(signingCertDer);
                // ESSCertIDv2 = SEQUENCE { certHash OCTET STRING }
                // hashAlgorithm omis (DEFAULT sha256, DER encoding cere omiterea DEFAULT)
                ASN1EncodableVector essCertIdV2 = new ASN1EncodableVector();
                essCertIdV2.add(new DEROctetString(certHash));

                ASN1EncodableVector certIds = new ASN1EncodableVector();
                certIds.add(new DERSequence(essCertIdV2));

                // SigningCertificateV2 = SEQUENCE { SEQUENCE OF ESSCertIDv2 }
                ASN1EncodableVector scv2 = new ASN1EncodableVector();
                scv2.add(new DERSequence(certIds));

                attrs.add(new Attribute(
                        new ASN1ObjectIdentifier(OID_SIGNING_CERT_V2),
                        new DERSet(new DERSequence(scv2))
                ));
                log.debug("buildSignedAttrsDer: signing-certificate-v2 adăugat (certHashLen=32)");
            }

            byte[] der = new DERSet(attrs).getEncoded(ASN1Encoding.DER);
            log.debug("buildSignedAttrsDer: signedAttrs DER len={}", der.length);
            return der;
        } catch (Exception e) {
            throw new RuntimeException("Nu am putut construi signedAttrs DER", e);
        }
    }

    // Overload backward-compat (fără cert)
    static byte[] buildSignedAttrsDer(byte[] documentDigest) {
        return buildSignedAttrsDer(documentDigest, null);
    }

    // ── ECDSA raw r||s → DER SEQUENCE converter ───────────────────────────────

    static byte[] normalizeEcdsaSignature(X509CertificateHolder leafHolder, byte[] signatureBytes) {
        String pkAlg = leafHolder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId();
        if (!OID_EC_PUBLIC_KEY.equals(pkAlg)) {
            log.debug("normalizeEcdsaSignature: RSA, fara conversie (len={})", signatureBytes.length);
            return signatureBytes;
        }
        if (signatureBytes.length == 64 && (signatureBytes[0] & 0xFF) != 0x30) {
            log.info("normalizeEcdsaSignature: ECDSA raw r||s detectat → DER SEQUENCE");
            try {
                byte[] r = Arrays.copyOfRange(signatureBytes, 0, 32);
                byte[] s = Arrays.copyOfRange(signatureBytes, 32, 64);
                ASN1EncodableVector seq = new ASN1EncodableVector();
                seq.add(new ASN1Integer(new java.math.BigInteger(1, r)));
                seq.add(new ASN1Integer(new java.math.BigInteger(1, s)));
                byte[] derSig = new DERSequence(seq).getEncoded(ASN1Encoding.DER);
                log.info("normalizeEcdsaSignature: DER generat (len={})", derSig.length);
                return derSig;
            } catch (Exception e) {
                log.warn("normalizeEcdsaSignature: conversie esuata, bytes originali", e);
                return signatureBytes;
            }
        }
        log.debug("normalizeEcdsaSignature: ECDSA deja DER sau format extins (len={})", signatureBytes.length);
        return signatureBytes;
    }

    // ── RFC 3161 TSA timestamp ────────────────────────────────────────────────
    //
    // Timestamp-ul acoperă signatureValue din SignerInfo.
    // Fără el, Adobe afișează "Signing time from signer's clock" și nu poate face LTV.
    // Cu el, Adobe știe că certificatul era valid la momentul semnării.

    static byte[] fetchTsaTimestamp(byte[] signatureBytes, String tsaUrl) {
        if (tsaUrl == null || tsaUrl.isBlank()) return null;
        try {
            log.info("TSA: requesting timestamp from {}", tsaUrl);
            byte[] msgImprint = sha256(signatureBytes);

            TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
            gen.setCertReq(true);
            TimeStampRequest tsq = gen.generate(
                    TSPAlgorithms.SHA256, msgImprint,
                    BigInteger.valueOf(System.currentTimeMillis())
            );
            byte[] tsqBytes = tsq.getEncoded();

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(tsaUrl))
                    .header("Content-Type", "application/timestamp-query")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(tsqBytes))
                    .timeout(Duration.ofSeconds(20))
                    .build();
            HttpResponse<byte[]> resp = client.send(req, HttpResponse.BodyHandlers.ofByteArray());

            if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                log.warn("TSA: HTTP {} de la {} — timestamp omis", resp.statusCode(), tsaUrl);
                return null;
            }

            TimeStampResponse tsr = new TimeStampResponse(resp.body());
            tsr.validate(tsq);
            byte[] tstBytes = tsr.getTimeStampToken().getEncoded();
            log.info("TSA: timestamp obtinut cu succes (len={})", tstBytes.length);
            return tstBytes;
        } catch (Exception e) {
            log.warn("TSA: eroare la obtinerea timestamp-ului (non-fatal, semnatura continua fara TST): {}", e.getMessage());
            return null;
        }
    }

    // ── CMS builder ───────────────────────────────────────────────────────────

    static byte[] buildCmsFromRawSignature(String signByteBase64,
                                           String certPem,
                                           List<String> chainPem,
                                           byte[] signedAttrsDerSet,
                                           String tsaUrl) {
        try {
            byte[] signatureBytes = Base64.getDecoder().decode(signByteBase64);
            log.info("buildCmsFromRawSignature: signByte len={}, firstByte=0x{}",
                    signatureBytes.length,
                    signatureBytes.length > 0 ? String.format("%02x", signatureBytes[0] & 0xFF) : "??");

            X509CertificateHolder leafHolder = new X509CertificateHolder(pemToDer(certPem));
            signatureBytes = normalizeEcdsaSignature(leafHolder, signatureBytes);

            // ── RFC 3161 timestamp (non-fatal dacă TSA e indisponibil) ─────────
            byte[] tstBytes = fetchTsaTimestamp(signatureBytes, tsaUrl);

            // ── Certificate chain ─────────────────────────────────────────────
            List<X509CertificateHolder> chain = new ArrayList<>();
            chain.add(leafHolder);
            if (chainPem != null) {
                for (String pem : chainPem) {
                    if (pem == null || pem.isBlank()) continue;
                    try {
                        X509CertificateHolder holder = new X509CertificateHolder(pemToDer(pem));
                        boolean dup = chain.stream().anyMatch(e -> {
                            try { return Arrays.equals(e.getEncoded(), holder.getEncoded()); }
                            catch (Exception ex) { return false; }
                        });
                        if (!dup) chain.add(holder);
                    } catch (Exception ex) {
                        log.warn("buildCmsFromRawSignature: cert invalid in chain, skipping: {}", ex.getMessage());
                    }
                }
            }
            log.info("buildCmsFromRawSignature: chain size={}", chain.size());

            // ── Algoritmi ─────────────────────────────────────────────────────
            AlgorithmIdentifier digestAlg = new DefaultDigestAlgorithmIdentifierFinder()
                    .find(new ASN1ObjectIdentifier(OID_SHA256));
            AlgorithmIdentifier sigAlg = signatureAlgorithmFor(leafHolder);

            // ── SignedAttrs ───────────────────────────────────────────────────
            ASN1Set signedAttrs = signedAttrsDerSet != null
                    ? ASN1Set.getInstance(ASN1Primitive.fromByteArray(signedAttrsDerSet))
                    : null;

            // ── Unsigned attrs: TSA timestamp ─────────────────────────────────
            ASN1Set unsignedAttrs = null;
            if (tstBytes != null) {
                Attribute tsAttr = new Attribute(
                        new ASN1ObjectIdentifier(OID_SIGNATURE_TST),
                        new DERSet(ASN1Primitive.fromByteArray(tstBytes))
                );
                ASN1EncodableVector uaVec = new ASN1EncodableVector();
                uaVec.add(tsAttr);
                unsignedAttrs = new DERSet(uaVec);
                log.info("buildCmsFromRawSignature: TSA timestamp adaugat ca unsignedAttr");
            }

            // ── SignerInfo ────────────────────────────────────────────────────
            SignerIdentifier sid = new SignerIdentifier(new IssuerAndSerialNumber(
                    leafHolder.getIssuer(), leafHolder.getSerialNumber()));

            SignerInfo signerInfo = new SignerInfo(
                    sid, digestAlg, signedAttrs, sigAlg,
                    new DEROctetString(signatureBytes),
                    unsignedAttrs  // ← timestamp RFC 3161
            );

            // ── Certificate bag ───────────────────────────────────────────────
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

    // Overload backward-compat (fara TSA)
    static byte[] buildCmsFromRawSignature(String signByteBase64,
                                           String certPem,
                                           List<String> chainPem,
                                           byte[] signedAttrsDerSet) {
        return buildCmsFromRawSignature(signByteBase64, certPem, chainPem, signedAttrsDerSet, null);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static AlgorithmIdentifier signatureAlgorithmFor(X509CertificateHolder holder) {
        String pkAlg = holder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId();
        if (OID_EC_PUBLIC_KEY.equals(pkAlg))
            return new AlgorithmIdentifier(new ASN1ObjectIdentifier(OID_ECDSA_SHA256));
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier(OID_RSA), DERNull.INSTANCE);
    }

    static X509Certificate parseCertificate(byte[] der) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der));
        } catch (Exception e) { throw new RuntimeException("Certificat X.509 invalid", e); }
    }

    static byte[] pemToDer(String pem) {
        String body = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(body);
    }
}
