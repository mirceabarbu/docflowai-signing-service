# DocFlowAI STS PAdES Service

Acest proiect este un **microserviciu Java/Spring Boot deployable** pentru a separa partea sensibilă de PAdES de aplicația Node DocFlowAI.

## Ce face acum
- pornește și se poate deploya pe Railway / Docker
- expune endpointuri stabile pentru integrarea cu DocFlowAI:
  - `GET /api/health`
  - `POST /api/pades/prepare`
  - `POST /api/pades/finalize`
  - `POST /api/pades/inspect`
- validează payloadurile și întoarce contractele JSON pe care le poate consuma DocFlowAI
- include locurile exacte unde trebuie introdusă logica PAdES externă cu iText

## Foarte important
Acest proiect este **scaffold deployable**, nu implementare criptografică finală. L-am făcut astfel ca să poți:
1. separa arhitectura imediat;
2. face deploy separat;
3. lega DocFlowAI de endpointuri stabile;
4. înlocui apoi logica internă fără să mai atingi fluxurile Node.

Partea de **PAdES extern valid Adobe cu STS** trebuie implementată și testată end-to-end cu certificatele și documentele tale reale.

## De ce această separare
STS documentează că serviciul primește doar hash-uri, iar încapsularea PADES/CADES/XADES rămâne la platforma client. Certificatul utilizatorului se poate lua din `/userinfo`, iar semnătura brută vine din `/api/v1/callback` prin `signByte`.

## Variabile de mediu
- `PORT` - implicit `8085`
- `APP_MODE` - implicit `scaffold`
- `LOG_LEVEL_ROOT` - implicit `INFO`

## Local
```bash
mvn spring-boot:run
```

## Docker local
```bash
docker build -t docflowai-sts-pades-service .
docker run -p 8085:8085 docflowai-sts-pades-service
```

## Railway
1. creezi un serviciu nou din acest folder / repo
2. Railway detectează Dockerfile
3. setezi doar `PORT` dacă vrei alt port
4. deploy

## Endpointuri
### GET /api/health
Răspuns de stare.

### POST /api/pades/prepare
Primește PDF-ul, datele semnăturii și întoarce contractul de pregătire.

### POST /api/pades/finalize
Primește PDF-ul pregătit + `signByte` + certificatul și întoarce contractul finalizării.

### POST /api/pades/inspect
Inspecție minimă a payloadului PDF.

## Pașii următori în DocFlowAI
Vezi fișierul `DOCFLOWAI_NEXT_STEPS.md`.

## Observație privind iText
Am inclus dependențe iText 8.x pentru că documentația oficială iText descrie semnarea externă prin `PdfSigner.signExternalContainer(...)` și semnarea diferențiată prin `signDeferred(...)`, iar Spring Boot suportă Java 21 pe versiunile moderne 3.x. Vezi sursele oficiale:
- iText API `PdfSigner.signExternalContainer(...)`
- Spring Boot system requirements / Maven plugin
