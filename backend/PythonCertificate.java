// PythonCertificate.java
package com.ma.dlp.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "python_certificates")
@Data
public class PythonCertificate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String deviceId;

    @Column(unique = true)
    private String certificateId;

    private LocalDateTime uploadedAt;

    @Column(name = "`generated`")
    private String generated;

    @Column(name = "`valid_until`")
    private String validUntil;

    private String issuer;
    private String recipient;
    private String device;

    @Column(columnDefinition = "TEXT")
    private String securityMetricsJson; // Store as JSON string

    @Column(columnDefinition = "TEXT")
    private String detailedAnalysisJson; // Store as JSON string

    @Column(columnDefinition = "TEXT")
    private String recommendationsJson; // Store as JSON string

    @Column(columnDefinition = "TEXT")
    private String signatureJson; // Store as JSON string

    // JSON properties that will be serialized
    @JsonProperty("securityMetrics")
    public Map<String, Object> getSecurityMetrics() {
        if (securityMetricsJson != null && !securityMetricsJson.isEmpty()) {
            try {
                return new ObjectMapper().readValue(securityMetricsJson, new TypeReference<Map<String, Object>>() {});
            } catch (JsonProcessingException e) {
                return new HashMap<>();
            }
        }
        return new HashMap<>();
    }

    public void setSecurityMetrics(Map<String, Object> securityMetrics) {
        this.securityMetricsJson = serializeToJson(securityMetrics);
    }

    @JsonProperty("detailedAnalysis")
    public Map<String, Object> getDetailedAnalysis() {
        if (detailedAnalysisJson != null && !detailedAnalysisJson.isEmpty()) {
            try {
                return new ObjectMapper().readValue(detailedAnalysisJson, new TypeReference<Map<String, Object>>() {});
            } catch (JsonProcessingException e) {
                return new HashMap<>();
            }
        }
        return new HashMap<>();
    }

    public void setDetailedAnalysis(Map<String, Object> detailedAnalysis) {
        this.detailedAnalysisJson = serializeToJson(detailedAnalysis);
    }

    @JsonProperty("recommendations")
    public List<Map<String, Object>> getRecommendations() {
        if (recommendationsJson != null && !recommendationsJson.isEmpty()) {
            try {
                return new ObjectMapper().readValue(recommendationsJson, new TypeReference<List<Map<String, Object>>>() {});
            } catch (JsonProcessingException e) {
                return new ArrayList<>();
            }
        }
        return new ArrayList<>();
    }

    public void setRecommendations(List<Map<String, Object>> recommendations) {
        this.recommendationsJson = serializeToJson(recommendations);
    }

    @JsonProperty("signature")
    public Map<String, Object> getSignature() {
        if (signatureJson != null && !signatureJson.isEmpty()) {
            try {
                return new ObjectMapper().readValue(signatureJson, new TypeReference<Map<String, Object>>() {});
            } catch (JsonProcessingException e) {
                return new HashMap<>();
            }
        }
        return new HashMap<>();
    }

    public void setSignature(Map<String, Object> signature) {
        this.signatureJson = serializeToJson(signature);
    }

    // Also expose the raw JSON fields for debugging
    @JsonProperty("securityMetricsJson")
    public String getSecurityMetricsJson() {
        return securityMetricsJson;
    }

    @JsonProperty("detailedAnalysisJson")
    public String getDetailedAnalysisJson() {
        return detailedAnalysisJson;
    }

    @JsonProperty("recommendationsJson")
    public String getRecommendationsJson() {
        return recommendationsJson;
    }

    @JsonProperty("signatureJson")
    public String getSignatureJson() {
        return signatureJson;
    }

    // Helper method to serialize to JSON
    private String serializeToJson(Object obj) {
        try {
            return new ObjectMapper().writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            if (obj instanceof Map) return "{}";
            if (obj instanceof List) return "[]";
            return "";
        }
    }

    // Standard getters and setters for database fields
    public void setSecurityMetricsJson(String securityMetricsJson) {
        this.securityMetricsJson = securityMetricsJson;
    }

    public void setDetailedAnalysisJson(String detailedAnalysisJson) {
        this.detailedAnalysisJson = detailedAnalysisJson;
    }

    public void setRecommendationsJson(String recommendationsJson) {
        this.recommendationsJson = recommendationsJson;
    }

    public void setSignatureJson(String signatureJson) {
        this.signatureJson = signatureJson;
    }

    // Standard getters and setters
    public String getCertificateId() {
        return certificateId;
    }

    public void setCertificateId(String certificateId) {
        this.certificateId = certificateId;
    }

    public String getDevice() {
        return device;
    }

    public void setDevice(String device) {
        this.device = device;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public String getGenerated() {
        return generated;
    }

    public void setGenerated(String generated) {
        this.generated = generated;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getRecipient() {
        return recipient;
    }

    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }

    public LocalDateTime getUploadedAt() {
        return uploadedAt;
    }

    public void setUploadedAt(LocalDateTime uploadedAt) {
        this.uploadedAt = uploadedAt;
    }

    public String getValidUntil() {
        return validUntil;
    }

    public void setValidUntil(String validUntil) {
        this.validUntil = validUntil;
    }
}