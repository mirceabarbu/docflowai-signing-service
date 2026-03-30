package ro.docflowai.signing.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class HealthController {

    @Value("${spring.application.name:docflowai-sts-pades-service}")
    private String appName;

    @Value("${APP_MODE:real}")
    private String mode;

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("service", appName);
        out.put("mode", mode);
        out.put("ts", OffsetDateTime.now().toString());
        return out;
    }
}
