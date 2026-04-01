package ro.docflowai.signing.controller;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ro.docflowai.signing.dto.*;
import ro.docflowai.signing.service.PadesCreateFieldsService;
import ro.docflowai.signing.service.PadesFinalizeService;
import ro.docflowai.signing.service.PadesInspectService;
import ro.docflowai.signing.service.PadesPrepareService;

@RestController
@RequestMapping("/api/pades")
public class PadesController {

    private final PadesPrepareService prepareService;
    private final PadesFinalizeService finalizeService;
    private final PadesInspectService inspectService;
    private final PadesCreateFieldsService createFieldsService;

    public PadesController(PadesPrepareService prepareService,
                           PadesFinalizeService finalizeService,
                           PadesInspectService inspectService,
                           PadesCreateFieldsService createFieldsService) {
        this.prepareService      = prepareService;
        this.finalizeService     = finalizeService;
        this.inspectService      = inspectService;
        this.createFieldsService = createFieldsService;
    }

    @PostMapping("/prepare")
    public PrepareResponse prepare(@Valid @RequestBody PrepareRequest request) {
        return prepareService.prepare(request);
    }

    @PostMapping("/finalize")
    public FinalizeResponse finalizeSignature(@Valid @RequestBody FinalizeRequest request) {
        return finalizeService.finalizeSignature(request);
    }

    @PostMapping("/inspect")
    public InspectResponse inspect(@Valid @RequestBody InspectRequest request) {
        return inspectService.inspect(request);
    }

    /**
     * b251: Creeaza campuri AcroForm /Sig folosind iText (nu pdf-lib).
     * Apelat la creare flux, dupa stampFooterOnPdf (care deseneaza vizualul).
     * iText-created fields sunt recunoscute de iText la semnare fara "reparare" → PAdES multi-sign corect.
     */
    @PostMapping("/create-fields")
    public CreateFieldsResponse createFields(@RequestBody CreateFieldsRequest request) {
        return createFieldsService.createFields(request);
    }
}
