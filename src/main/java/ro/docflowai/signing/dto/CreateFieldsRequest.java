package ro.docflowai.signing.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.List;

public class CreateFieldsRequest {
    @NotBlank public String pdfBase64;
    public List<FieldDef> fields;

    public static class FieldDef {
        public String fieldName;
        public Float x;
        public Float y;
        public Float w;
        public Float h;
        public Integer page;  // 1-based
    }
}
