// PythonAppUsage.java
package com.ma.dlp.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import lombok.Data;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;
@Entity
@Table(name = "python_app_usage")
@Data
public class PythonAppUsage {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String deviceId;

    private LocalDateTime timestamp;
    private String currentApp;
    private Double currentSessionDuration;
    private Integer totalAppsTracked;
    private Double totalTimeTracked;
    private Double activeUsageTime; 

    public Double getActiveUsageTime() {
        return activeUsageTime;
    }
    
    public void setActiveUsageTime(Double activeUsageTime) {
        this.activeUsageTime = activeUsageTime;
    }

    @Column(columnDefinition = "TEXT")
    private String topAppsJson;

    @Column(columnDefinition = "TEXT")
    private String categoryBreakdownJson;

    @Transient
    private List<Map<String, Object>> topApps;

    @Transient
    private Map<String, Object> categoryBreakdown = new HashMap<>();

    private static final ObjectMapper objectMapper = new ObjectMapper();

    // Getter for topApps with JSON conversion
    public List<Map<String, Object>> getTopApps() {
        if (topApps == null && topAppsJson != null && !topAppsJson.isEmpty()) {
            try {
                topApps = objectMapper.readValue(topAppsJson, new TypeReference<List<Map<String, Object>>>() {});
            } catch (JsonProcessingException e) {
                topApps = List.of();
            }
        }
        return topApps;
    }

    // Setter for topApps with JSON conversion
    public void setTopApps(List<Map<String, Object>> topApps) {
        this.topApps = topApps;
        try {
            this.topAppsJson = objectMapper.writeValueAsString(topApps);
        } catch (JsonProcessingException e) {
            this.topAppsJson = "[]";
        }
    }

    // Getter for categoryBreakdown with JSON conversion
    public Map<String, Object> getCategoryBreakdown() {
        if (categoryBreakdown == null && categoryBreakdownJson != null && !categoryBreakdownJson.isEmpty()) {
            try {
                categoryBreakdown = objectMapper.readValue(categoryBreakdownJson, new TypeReference<Map<String, Object>>() {});
            } catch (JsonProcessingException e) {
                categoryBreakdown = new HashMap<>();
            }
        }
        return categoryBreakdown;
    }

    // Setter for categoryBreakdown with JSON conversion
    public void setCategoryBreakdown(Map<String, Object> categoryBreakdown) {
        this.categoryBreakdown = categoryBreakdown;
        try {
            this.categoryBreakdownJson = objectMapper.writeValueAsString(categoryBreakdown);
        } catch (JsonProcessingException e) {
            this.categoryBreakdownJson = "{}";
        }
    }

    // Direct getter/setter for JSON fields (for database operations)
    public String getTopAppsJson() {
        return topAppsJson;
    }

    public void setTopAppsJson(String topAppsJson) {
        this.topAppsJson = topAppsJson;
    }

    public String getCategoryBreakdownJson() {
        return categoryBreakdownJson;
    }

    public void setCategoryBreakdownJson(String categoryBreakdownJson) {
        this.categoryBreakdownJson = categoryBreakdownJson;
    }

//    public Map<String, Object> getCategoryBreakdown() {
//        return categoryBreakdown;
//    }
//
//    public void setCategoryBreakdown(Map<String, Object> categoryBreakdown) {
//        this.categoryBreakdown = categoryBreakdown;
//    }
//
//    public List<Map<String, Object>> getTopApps() {
//        return topApps;
//    }
//
//    public void setTopApps(List<Map<String, Object>> topApps) {
//        this.topApps = topApps;
//    }

    public String getCurrentApp() {
        return currentApp;
    }

    public void setCurrentApp(String currentApp) {
        this.currentApp = currentApp;
    }

    public Double getCurrentSessionDuration() {
        return currentSessionDuration;
    }

    public void setCurrentSessionDuration(Double currentSessionDuration) {
        this.currentSessionDuration = currentSessionDuration;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public Integer getTotalAppsTracked() {
        return totalAppsTracked;
    }

    public void setTotalAppsTracked(Integer totalAppsTracked) {
        this.totalAppsTracked = totalAppsTracked;
    }

    public Double getTotalTimeTracked() {
        return totalTimeTracked;
    }

    public void setTotalTimeTracked(Double totalTimeTracked) {
        this.totalTimeTracked = totalTimeTracked;
    }
}