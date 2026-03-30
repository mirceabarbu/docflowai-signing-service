# Ce faci mai departe în DocFlowAI

## 1. Deploy microserviciul
- deployezi acest proiect pe Railway
- copiezi URL-ul rezultat

Exemplu:
```env
SIGNING_SERVICE_URL=https://docflowai-sts-pades-service.up.railway.app
```

## 2. Adaugi variabila în DocFlowAI
În serviciul Node adaugi:
```env
SIGNING_SERVICE_URL=https://...url-ul-tău...
```

## 3. Nu mai injecta CMS în Node
În arhiva ta actuală, zona critică este în:
- `server/routes/flows/cloud-signing.mjs`
- `server/routes/flows/bulk-signing.mjs`
- `server/signing/pades.mjs`

### Regula nouă
Node nu mai trebuie să facă:
- `preparePadesDoc(...)`
- `injectCms(...)`
- redesenare după semnare

Node trebuie doar să:
1. obțină tokenul STS;
2. ia certificatul din `/userinfo`;
3. trimită PDF-ul la microserviciul Java `/api/pades/prepare`;
4. trimită hash-ul primit la STS `/api/v1/signature`;
5. facă polling la STS `/api/v1/callback`;
6. trimită `preparedPdfBase64 + signByte + certificatePem` la `/api/pades/finalize`;
7. salveze PDF-ul final fără alte modificări.

## 4. Locul exact de modificare în flow-ul STS
### A. În `server/routes/flows/cloud-signing.mjs`
La inițierea semnării STS, în loc să mai folosești local `preparePadesDoc(...)`, faci request HTTP la Java:

```js
const prepRes = await fetch(`${process.env.SIGNING_SERVICE_URL}/api/pades/prepare`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    pdfBase64: data.signedPdfB64 || data.pdfB64,
    fieldName: `sig_${idx + 1}`,
    signerName: signer.name || signer.email,
    signerRole: signer.role || signer.attribute || '',
    reason: 'Semnare DocFlowAI',
    location: data.institution || 'DocFlowAI',
    contactInfo: signer.email || '',
    page: 1,
    x: 100,
    y: 100,
    width: 180,
    height: 50,
    useSignedAttributes: true,
    subFilter: 'ETSI.CAdES.detached'
  })
}).then(r => r.json());
```

### B. Salvezi în flow
```js
data[`_javaPreparedPdf_${idx}`] = prepRes.preparedPdfBase64;
data[`_javaToBeSigned_${idx}`] = prepRes.toBeSignedDigestBase64;
```

### C. Trimiți la STS hash-ul de la Java
```js
padesHashBase64: prepRes.toBeSignedDigestBase64
```

### D. În polling
În loc de `injectCms(...)`, faci:
```js
const finalizeRes = await fetch(`${process.env.SIGNING_SERVICE_URL}/api/pades/finalize`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    preparedPdfBase64: data[`_javaPreparedPdf_${idx}`],
    fieldName: `sig_${idx + 1}`,
    signByteBase64: pollResult.signByte,
    certificatePem: signer.stsCertPem || '',
    certificateChainPem: [],
    useSignedAttributes: true,
    subFilter: 'ETSI.CAdES.detached'
  })
}).then(r => r.json());

const signedPdfB64 = finalizeRes.signedPdfBase64;
```

## 5. Scoți complet redesenarea după semnare
În `cloud-signing.mjs`, blocul cu `pdf-lib` care redesenează appearance-ul după `injectCms(...)` trebuie scos complet.

## 6. Bulk signing
Aplici aceeași regulă în `server/routes/flows/bulk-signing.mjs`:
- `prepare` în Java
- trimis hash la STS
- `finalize` în Java
- Node doar salvează

## 7. Ce păstrezi în Node
- `STSCloudProvider.mjs`
- OAuth PKCE
- `/userinfo`
- `/api/v1/signature`
- `/api/v1/callback`
- flow state / notificări / DB

## 8. Ce teste faci imediat după integrare
1. un PDF simplu
2. un singur semnatar
3. fără semnături multiple
4. fără footer sau redesenare după semnare
5. verificare Adobe

## 9. Ce nu faci
- nu mai deschizi PDF-ul final semnat cu `pdf-lib` ca să scrii ceva peste el
- nu mai salvezi din nou PDF-ul final semnat
- nu mai amesteci hash-ul documentului cu hash-ul `signedAttrs`
