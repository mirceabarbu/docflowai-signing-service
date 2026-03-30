package ro.docflowai.signing.service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

final class DerCmsSupport {
    private DerCmsSupport() {}

    static final String OID_SIGNED_DATA  = "2a864886f70d010702";
    static final String OID_DATA         = "2a864886f70d010701";
    static final String OID_SHA256       = "608648016503040201";
    static final String OID_RSA          = "2a864886f70d010101";
    static final String OID_ECDSA_SHA256 = "2a8648ce3d040302";
    static final String SUBFILTER_CADES  = "ETSI.CAdES.detached";
    static final String SUBFILTER_ADBE   = "adbe.pkcs7.detached";

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

    static String sha256Base64(byte[] data) {
        return Base64.getEncoder().encodeToString(sha256(data));
    }

    static byte[] buildSignedAttrsImplicit(byte[] documentDigest) {
        byte[] contentTypeAttr = seq(concat(
                oid("2a864886f70d010903"),
                set(seq(oid(OID_DATA)))
        ));
        byte[] msgDigestAttr = seq(concat(
                oid("2a864886f70d010904"),
                set(octetString(documentDigest))
        ));
        byte[] innerSet = concat(contentTypeAttr, msgDigestAttr);
        return tlv(0xA0, innerSet);
    }

    static String calcSignedAttrsHashBase64(byte[] signedAttrsImplicit) {
        byte[] hashable = new byte[signedAttrsImplicit.length];
        System.arraycopy(signedAttrsImplicit, 0, hashable, 0, signedAttrsImplicit.length);
        hashable[0] = 0x31;
        return Base64.getEncoder().encodeToString(sha256(hashable));
    }

    static byte[] buildCmsFromRawSignature(String signByteBase64,
                                           String certPem,
                                           List<String> chainPem,
                                           byte[] signedAttrsDer) {
        try {
            byte[] signatureBytes = Base64.getDecoder().decode(signByteBase64);
            List<byte[]> derChain = new ArrayList<>();
            byte[] leafDer = pemToDer(certPem);
            derChain.add(leafDer);
            if (chainPem != null) {
                for (String pem : chainPem) {
                    if (pem == null || pem.isBlank()) continue;
                    byte[] der = pemToDer(pem);
                    boolean duplicate = derChain.stream().anyMatch(existing -> java.util.Arrays.equals(existing, der));
                    if (!duplicate) derChain.add(der);
                }
            }

            IssuerSerial issuerSerial = parseIssuerAndSerial(leafDer);
            X509Certificate cert = parseCertificate(leafDer);
            boolean isEc = cert.getPublicKey() != null && cert.getPublicKey().getAlgorithm() != null
                    && cert.getPublicKey().getAlgorithm().toUpperCase().contains("EC");

            byte[] sigAlgId = isEc ? seq(oid(OID_ECDSA_SHA256)) : algId(OID_RSA);
            byte[] signerInfo;
            if (signedAttrsDer != null) {
                signerInfo = seq(concat(
                        int1(1),
                        seq(concat(issuerSerial.issuerBytes, issuerSerial.serialBytes)),
                        algId(OID_SHA256),
                        signedAttrsDer,
                        sigAlgId,
                        octetString(signatureBytes)
                ));
            } else {
                signerInfo = seq(concat(
                        int1(1),
                        seq(concat(issuerSerial.issuerBytes, issuerSerial.serialBytes)),
                        algId(OID_SHA256),
                        sigAlgId,
                        octetString(signatureBytes)
                ));
            }

            ByteArrayOutputStream certs = new ByteArrayOutputStream();
            for (byte[] der : derChain) certs.write(der);

            byte[] signedData = seq(concat(
                    int1(1),
                    set(algId(OID_SHA256)),
                    seq(oid(OID_DATA)),
                    ctx0(certs.toByteArray()),
                    set(signerInfo)
            ));
            return seq(concat(oid(OID_SIGNED_DATA), ctx0(signedData)));
        } catch (Exception e) {
            throw new RuntimeException("Nu am putut construi CMS din signByte", e);
        }
    }

    static X509Certificate parseCertificate(byte[] der) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
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

    static class IssuerSerial {
        final byte[] issuerBytes;
        final byte[] serialBytes;

        IssuerSerial(byte[] issuerBytes, byte[] serialBytes) {
            this.issuerBytes = issuerBytes;
            this.serialBytes = serialBytes;
        }
    }

    static IssuerSerial parseIssuerAndSerial(byte[] certDer) {
        try {
            int pos = 0;
            pos++; // Certificate sequence tag
            int[] out = readLen(certDer, pos);
            pos = out[1];

            pos++; // TBS sequence tag
            out = readLen(certDer, pos);
            pos = out[1];

            if ((certDer[pos] & 0xFF) == 0xA0) {
                int start = pos;
                pos++;
                out = readLen(certDer, pos);
                pos = out[1] + out[0];
            }

            int serialStart = pos;
            pos++;
            out = readLen(certDer, pos);
            pos = out[1] + out[0];
            byte[] serialBytes = slice(certDer, serialStart, pos);

            pos++; // signature alg tag
            out = readLen(certDer, pos);
            pos = out[1] + out[0];

            int issuerStart = pos;
            pos++;
            out = readLen(certDer, pos);
            pos = out[1] + out[0];
            byte[] issuerBytes = slice(certDer, issuerStart, pos);

            return new IssuerSerial(issuerBytes, serialBytes);
        } catch (Exception e) {
            throw new RuntimeException("Nu am putut extrage issuer+serial din DER", e);
        }
    }

    private static int[] readLen(byte[] data, int pos) {
        int b = data[pos] & 0xFF;
        if ((b & 0x80) == 0) return new int[]{b, pos + 1};
        int n = b & 0x7F;
        int len = 0;
        int cursor = pos + 1;
        for (int i = 0; i < n; i++) len = (len << 8) | (data[cursor + i] & 0xFF);
        return new int[]{len, cursor + n};
    }

    private static byte[] slice(byte[] src, int start, int end) {
        byte[] out = new byte[end - start];
        System.arraycopy(src, start, out, 0, out.length);
        return out;
    }

    static byte[] concat(byte[]... arrays) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            for (byte[] a : arrays) {
                if (a != null) baos.write(a);
            }
            return baos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] tlv(int tag, byte[] content) {
        return concat(new byte[]{(byte) tag}, encodeLen(content.length), content);
    }

    static byte[] seq(byte[] content) { return tlv(0x30, content); }
    static byte[] set(byte[] content) { return tlv(0x31, content); }
    static byte[] ctx0(byte[] content) { return tlv(0xA0, content); }
    static byte[] oid(String hex) {
        byte[] body = hexStringToBytes(hex);
        return concat(new byte[]{0x06, (byte) body.length}, body);
    }
    static byte[] int1(int value) { return new byte[]{0x02, 0x01, (byte) value}; }
    static byte[] octetString(byte[] data) { return concat(new byte[]{0x04}, encodeLen(data.length), data); }
    static byte[] algId(String oidHex) { return seq(concat(oid(oidHex), new byte[]{0x05, 0x00})); }

    static byte[] encodeLen(int len) {
        if (len < 128) return new byte[]{(byte) len};
        int tmp = len;
        int count = 0;
        while (tmp > 0) { count++; tmp >>= 8; }
        byte[] out = new byte[1 + count];
        out[0] = (byte) (0x80 | count);
        for (int i = count; i > 0; i--) {
            out[i] = (byte) (len & 0xFF);
            len >>= 8;
        }
        return out;
    }

    static byte[] hexStringToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
    }
}
