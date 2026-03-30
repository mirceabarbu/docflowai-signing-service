package ro.docflowai.signing.dto;

import java.util.ArrayList;
import java.util.List;

public class InspectResponse {
    public Integer pdfBytes;
    public Boolean base64Decoded;
    public List<String> notes = new ArrayList<>();
    public String mode;
}
