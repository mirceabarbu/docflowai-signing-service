package ro.docflowai.signing.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import jakarta.annotation.PostConstruct;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class HealthController {

    private static final Logger log = LoggerFactory.getLogger(HealthController.class);

    // ── Versiune hardcodată — schimbă la fiecare build ─────────────────────
    private static final String BUILD_VERSION = "b242";
    private static final String BUILD_DATE    = "2026-03-31-b242";
    // ────────────────────────────────────────────────────────────────────────

    @Value("${spring.application.name:docflowai-sts-pades-service}")
    private String appName;

    @Value("${APP_MODE:real}")
    private String mode;

    @Value("${tsa.url:http://timestamp.digicert.com}")
    private String tsaUrl;

    @PostConstruct
    public void logStartup() {
        log.info("╔══════════════════════════════════════════════════════╗");
        log.info("║  DocFlowAI STS PAdES Service  —  BUILD {}  ({})  ║", BUILD_VERSION, BUILD_DATE);
        log.info("║  mode={}  tsa={}  ║", mode, tsaUrl);
        log.info("╚══════════════════════════════════════════════════════╝");
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("service", appName);
        out.put("build", BUILD_VERSION);
        out.put("buildDate", BUILD_DATE);
        out.put("mode", mode);
        out.put("tsaUrl", tsaUrl);
        out.put("ts", OffsetDateTime.now().toString());
        return out;
    }
}
