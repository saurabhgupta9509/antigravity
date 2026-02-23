package com.ma.dlp.service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ma.dlp.Repository.PythonAppUsageRepository;
import com.ma.dlp.Repository.PythonCertificateRepository;
import com.ma.dlp.Repository.PythonDeviceRepository;
import com.ma.dlp.Repository.PythonLogRepository;
import com.ma.dlp.Repository.PythonUrlDataRepository;
import com.ma.dlp.model.PythonAppUsage;
import com.ma.dlp.model.PythonCertificate;
import com.ma.dlp.model.PythonDevice;
import com.ma.dlp.model.PythonLog;
import com.ma.dlp.model.PythonUrlData;

@Service
public class PythonClientService {

    private static final Logger logger = LoggerFactory.getLogger(PythonClientService.class);
    private final PythonDeviceRepository pythonDeviceRepository;
    private final PythonLogRepository pythonLogRepository;
    private final PythonUrlDataRepository pythonUrlDataRepository;
    private final PythonAppUsageRepository pythonAppUsageRepository;
    private final PythonCertificateRepository pythonCertificateRepository;
    private final ObjectMapper objectMapper;

    public PythonClientService(PythonDeviceRepository pythonDeviceRepository, PythonLogRepository pythonLogRepository,
            PythonUrlDataRepository pythonUrlDataRepository, PythonAppUsageRepository pythonAppUsageRepository,
            PythonCertificateRepository pythonCertificateRepository, ObjectMapper objectMapper) {
        this.pythonDeviceRepository = pythonDeviceRepository;
        this.pythonLogRepository = pythonLogRepository;
        this.pythonUrlDataRepository = pythonUrlDataRepository;
        this.pythonAppUsageRepository = pythonAppUsageRepository;
        this.pythonCertificateRepository = pythonCertificateRepository;
        this.objectMapper = objectMapper;
    }

    // Device Registration
    @Transactional
    public PythonDevice registerDevice(Map<String, Object> request) {
        String deviceId = (String) request.get("deviceId");

        Optional<PythonDevice> existingDevice = pythonDeviceRepository.findByDeviceId(deviceId);
        if (existingDevice.isPresent()) {
            PythonDevice device = existingDevice.get();
            device.setLastHeartbeat(LocalDateTime.now());
            device.setStatus("active");
            return pythonDeviceRepository.save(device);
        }

        PythonDevice device = new PythonDevice();
        device.setDeviceId(deviceId);
        device.setUserId((String) request.get("userId"));
        device.setDeviceName((String) request.get("deviceName"));
        device.setPlatform((String) request.get("platform"));
        device.setMonitorVersion((String) request.get("monitorVersion"));
        device.setFirstSeen(LocalDateTime.now());
        device.setLastHeartbeat(LocalDateTime.now());
        device.setLastSeen(LocalDateTime.now());
        device.setStatus("active");

        try {
            // Store additional info as JSON
            String deviceInfo = objectMapper.writeValueAsString(request);
            device.setDeviceInfo(deviceInfo);
        } catch (Exception e) {
            logger.warn("Failed to serialize device info: {}", e.getMessage());
        }

        return pythonDeviceRepository.save(device);
    }

    // Heartbeat
    @Transactional
    public void updateHeartbeat(String deviceId) {
        pythonDeviceRepository.findByDeviceId(deviceId).ifPresent(device -> {
            device.setLastHeartbeat(LocalDateTime.now());
            device.setLastSeen(LocalDateTime.now());
            pythonDeviceRepository.save(device);
        });
    }

    // Log Upload
    @Transactional
    public void saveLog(Map<String, Object> logData) {
        PythonLog pythonLog = new PythonLog();
        pythonLog.setDeviceId((String) logData.get("deviceId"));
        pythonLog.setLogType((String) logData.get("logType")); // Make sure it's "logType" not "loggerType"
        pythonLog.setLogContent((String) logData.get("logContent"));
        pythonLog.setTimestamp(LocalDateTime.now());

        // Handle fileSize properly
        Object fileSizeObj = logData.get("fileSize");
        if (fileSizeObj != null) {
            if (fileSizeObj instanceof Integer) {
                pythonLog.setFileSize((Integer) fileSizeObj);
            } else if (fileSizeObj instanceof String) {
                try {
                    pythonLog.setFileSize(Integer.parseInt((String) fileSizeObj));
                } catch (NumberFormatException e) {
                    pythonLog.setFileSize(0);
                }
            } else {
                pythonLog.setFileSize(0);
            }
        } else {
            pythonLog.setFileSize(0);
        }

        pythonLogRepository.save(pythonLog);
        logger.info("📝 Python log saved - Device: {}, Type: {}", pythonLog.getDeviceId(), pythonLog.getLogType());
    }

    // URL Data Upload
    @Transactional
    public void saveUrlData(Map<String, Object> urlData) {
        logger.info("📊 Python URL Data Received - Device: {}, Data: {}", urlData.get("deviceId"), urlData.toString());
    
        PythonUrlData data = new PythonUrlData();
        data.setDeviceId((String) urlData.get("deviceId"));
        data.setTimestamp(LocalDateTime.now());

        try {
            // Log what we're receiving
            List<String> urls = (List<String>) urlData.get("urls");
            logger.info("📊 URLs List: {}", urls);
            
            String urlsJson = objectMapper.writeValueAsString(urls);
            logger.info("📊 URLs JSON: {}", urlsJson);
            
            data.setUrls(urlsJson);
        } catch (Exception e) {
            logger.error("❌ Failed to serialize URLs: {}", e.getMessage(), e);
        }

        data.setBlockedCount((Integer) urlData.get("blockedCount"));
        data.setSuspiciousCount((Integer) urlData.get("suspiciousCount"));
        data.setTotalVisits((Integer) urlData.get("totalVisits"));

        pythonUrlDataRepository.save(data);
    }

    // App Usage Upload
    

@Transactional
public void saveAppUsage(Map<String, Object> appData) {
    logger.info("📱 ====== APP USAGE DEBUG START ======");
    logger.info("📱 Python App Data Received - Device: {}", appData.get("deviceId"));
    
    String deviceId = (String) appData.get("deviceId");
    LocalDateTime timestamp = LocalDateTime.now();
    
    // Get current date boundaries
    LocalDate today = timestamp.toLocalDate();
    LocalDateTime startOfDay = today.atStartOfDay();
    LocalDateTime endOfDay = today.plusDays(1).atStartOfDay();
    
    // Get today's existing records
    List<PythonAppUsage> todayUsages = getAppUsageByDeviceAndDateRange(deviceId, startOfDay, endOfDay);
    
    PythonAppUsage data = new PythonAppUsage();
    data.setDeviceId(deviceId);
    data.setTimestamp(timestamp);
    
    String currentApp = (String) appData.getOrDefault("currentApp", "Unknown");
    data.setCurrentApp(currentApp);
    logger.info("📱 Current App: {}", currentApp);
    
    // Handle current session duration
    Object sessionDuration = appData.get("currentSessionDuration");
    Double sessionDurationValue = 0.0;
    
    if (sessionDuration != null) {
        if (sessionDuration instanceof Double) {
            sessionDurationValue = (Double) sessionDuration;
        } else if (sessionDuration instanceof Integer) {
            sessionDurationValue = ((Integer) sessionDuration).doubleValue();
        } else if (sessionDuration instanceof String) {
            try {
                sessionDurationValue = Double.parseDouble((String) sessionDuration);
            } catch (NumberFormatException e) {
                logger.warn("❌ Failed to parse sessionDuration string: {}", sessionDuration);
            }
        }
    }
    data.setCurrentSessionDuration(sessionDurationValue);
    
    // Get other fields
    Object totalTime = appData.get("totalTimeTracked");
    if (totalTime != null) {
        if (totalTime instanceof Double) {
            data.setTotalTimeTracked((Double) totalTime);
        } else if (totalTime instanceof Integer) {
            data.setTotalTimeTracked(((Integer) totalTime).doubleValue());
        } else if (totalTime instanceof String) {
            try {
                data.setTotalTimeTracked(Double.parseDouble((String) totalTime));
            } catch (NumberFormatException e) {
                data.setTotalTimeTracked(0.0);
            }
        } else {
            data.setTotalTimeTracked(0.0);
        }
    } else {
        data.setTotalTimeTracked(0.0);
    }
    
    Object totalApps = appData.get("totalAppsTracked");
    if (totalApps != null) {
        if (totalApps instanceof Integer) {
            data.setTotalAppsTracked((Integer) totalApps);
        } else if (totalApps instanceof String) {
            try {
                data.setTotalAppsTracked(Integer.parseInt((String) totalApps));
            } catch (NumberFormatException e) {
                data.setTotalAppsTracked(0);
            }
        } else {
            data.setTotalAppsTracked(0);
        }
    } else {
        data.setTotalAppsTracked(0);
    }

    // ======== IMPORTANT: Calculate daily activeUsageTime ========
    Object activeTimeObj = appData.get("activeUsageTime");
    Double activeTimeValue;
    
    if (activeTimeObj != null) {
        if (activeTimeObj instanceof Double) {
            activeTimeValue = (Double) activeTimeObj;
        } else if (activeTimeObj instanceof Integer) {
            activeTimeValue = ((Integer) activeTimeObj).doubleValue();
        } else if (activeTimeObj instanceof String) {
            try {
                activeTimeValue = Double.parseDouble((String) activeTimeObj);
            } catch (NumberFormatException e) {
                // If it's a string that can't be parsed, treat it as session duration
                activeTimeValue = sessionDurationValue;
            }
        } else {
            activeTimeValue = sessionDurationValue;
        }
    } else {
        // If not provided, use session duration
        activeTimeValue = sessionDurationValue;
    }
    
    // Calculate daily total: previous total + current session
    Double previousDailyTotal = 0.0;
    if (!todayUsages.isEmpty()) {
        // Get the latest record for today
        PythonAppUsage latestToday = todayUsages.get(0);
        previousDailyTotal = latestToday.getActiveUsageTime() != null ? 
            latestToday.getActiveUsageTime() : 0.0;
    }
    
    Double newDailyTotal = previousDailyTotal + sessionDurationValue;
    data.setActiveUsageTime(newDailyTotal);
    
    logger.info("📱 Previous daily total: {}s", previousDailyTotal);
    logger.info("📱 Current session: {}s", sessionDurationValue);
    logger.info("📱 New daily total: {}s", newDailyTotal);
    
    // Handle topApps and categoryBreakdown
    try {
        Object topAppsObj = appData.get("topApps");
        if (topAppsObj instanceof List) {
            List<Map<String, Object>> topApps = (List<Map<String, Object>>) topAppsObj;
            data.setTopApps(topApps);
        } else {
            data.setTopApps(new ArrayList<>());
        }
        
        Object categoryObj = appData.get("categoryBreakdown");
        if (categoryObj instanceof Map) {
            Map<String, Object> categoryBreakdown = (Map<String, Object>) categoryObj;
            data.setCategoryBreakdown(categoryBreakdown);
        } else {
            data.setCategoryBreakdown(new HashMap<>());
        }
    } catch (Exception e) {
        logger.error("❌ Failed to serialize app data: {}", e.getMessage());
        data.setTopApps(new ArrayList<>());
        data.setCategoryBreakdown(new HashMap<>());
    }
    
    PythonAppUsage saved = pythonAppUsageRepository.save(data);
    logger.info("📱 App usage saved - ID: {}, Device: {}, Daily Total: {}s", 
        saved.getId(), saved.getDeviceId(), saved.getActiveUsageTime());
    logger.info("📱 ====== APP USAGE DEBUG END ======");
}
    // Certificate Upload
    @Transactional
    public void saveCertificate(Map<String, Object> certData) {
        PythonCertificate cert = new PythonCertificate();
        cert.setDeviceId((String) certData.get("deviceId"));

        // Generate certificateId if not provided
        String certId = (String) certData.get("certificateId");
        if (certId == null || certId.isEmpty()) {
            certId = "CERT-" + UUID.randomUUID().toString().substring(0, 8);
        }
        cert.setCertificateId(certId);

        cert.setUploadedAt(LocalDateTime.now());
        cert.setGenerated((String) certData.getOrDefault("generated", LocalDateTime.now().toString()));
        cert.setValidUntil((String) certData.getOrDefault("validUntil", LocalDateTime.now().plusYears(1).toString()));
        cert.setIssuer((String) certData.getOrDefault("issuer", "Cybersecurity Monitor"));
        cert.setRecipient((String) certData.getOrDefault("recipient", "Unknown User"));
        cert.setDevice((String) certData.getOrDefault("device", "Unknown Device"));

        try {
            // Security Metrics
            Object metricsObj = certData.get("securityMetrics");
            Map<String, Object> securityMetrics;
            if (metricsObj instanceof Map) {
                securityMetrics = (Map<String, Object>) metricsObj;
            } else {
                // Default metrics
                securityMetrics = new HashMap<>();
                securityMetrics.put("overall_score", 75.0);
                securityMetrics.put("grade", "C+");
                securityMetrics.put("threat_level", "medium");
                securityMetrics.put("scan_date", LocalDateTime.now().toString());
            }
            cert.setSecurityMetrics(securityMetrics);

            // Detailed Analysis
            Object analysisObj = certData.get("detailedAnalysis");
            Map<String, Object> detailedAnalysis;
            if (analysisObj instanceof Map) {
                detailedAnalysis = (Map<String, Object>) analysisObj;
            } else {
                detailedAnalysis = new HashMap<>();
                detailedAnalysis.put("scan_type", "full_system");
                detailedAnalysis.put("vulnerabilities_found", 0);
            }
            cert.setDetailedAnalysis(detailedAnalysis);

            // Recommendations
            Object recommendationsObj = certData.get("recommendations");
            List<Map<String, Object>> recommendations;
            if (recommendationsObj instanceof List) {
                recommendations = (List<Map<String, Object>>) recommendationsObj;
            } else {
                recommendations = new ArrayList<>();
                // Add default recommendations
                Map<String, Object> rec1 = new HashMap<>();
                rec1.put("priority", "high");
                rec1.put("action", "Update all software");
                rec1.put("description", "Keep your system updated");
                recommendations.add(rec1);
            }
            cert.setRecommendations(recommendations);

            // Signature
            Object signatureObj = certData.get("signature");
            Map<String, Object> signature;
            if (signatureObj instanceof Map) {
                signature = (Map<String, Object>) signatureObj;
            } else {
                signature = new HashMap<>();
                signature.put("algorithm", "SHA256");
                signature.put("verified", true);
                signature.put("timestamp", LocalDateTime.now().toString());
            }
            cert.setSignature(signature);
        } catch (Exception e) {
            logger.warn("Failed to serialize certificate data: {}", e.getMessage());
            // Set defaults
            Map<String, Object> defaultMetrics = new HashMap<>();
            defaultMetrics.put("overall_score", 50.0);
            defaultMetrics.put("grade", "F");
            defaultMetrics.put("threat_level", "high");
            cert.setSecurityMetrics(defaultMetrics);

            cert.setDetailedAnalysis(new HashMap<>());

            List<Map<String, Object>> defaultRecs = new ArrayList<>();
            Map<String, Object> rec = new HashMap<>();
            rec.put("priority", "critical");
            rec.put("action", "Immediate attention required");
            defaultRecs.add(rec);
            cert.setRecommendations(defaultRecs);

            cert.setSignature(new HashMap<>());
        }

        pythonCertificateRepository.save(cert);
        logger.info("📜 Python certificate saved - ID: {}, Device: {}", cert.getCertificateId(), cert.getDeviceId());
    }

    // Shutdown notification
    @Transactional
    public void handleShutdown(String deviceId) {
        pythonDeviceRepository.findByDeviceId(deviceId).ifPresent(device -> {
            device.setLastSeen(LocalDateTime.now());
            device.setStatus("shutdown");
            pythonDeviceRepository.save(device);
        });
    }

    // Get all devices
    public List<PythonDevice> getAllDevices() {
        return pythonDeviceRepository.findAllByOrderByLastHeartbeatDesc();
    }

    // Get device by ID
    public Optional<PythonDevice> getDeviceById(String deviceId) {
        return pythonDeviceRepository.findByDeviceId(deviceId);
    }

    // Get device logs
    public List<PythonLog> getDeviceLogs(String deviceId) {
        return pythonLogRepository.findByDeviceIdOrderByTimestampDesc(deviceId);
    }

    // Get device URL history
    public List<PythonUrlData> getDeviceUrlHistory(String deviceId) {
        return pythonUrlDataRepository.findByDeviceIdOrderByTimestampDesc(deviceId);
    }

    // Get device app usage history
    public List<PythonAppUsage> getDeviceAppUsageHistory(String deviceId) {
        return pythonAppUsageRepository.findByDeviceIdOrderByTimestampDesc(deviceId);
    }

    // Get device certificates
    public List<PythonCertificate> getDeviceCertificates(String deviceId) {
        return pythonCertificateRepository.findByDeviceIdOrderByUploadedAtDesc(deviceId);
    }

    // Cleanup old data
    @Scheduled(fixedRate = 3600000) // Every hour
    @Transactional
    public void cleanupInactiveDevices() {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(7); // 7 days inactive
        List<PythonDevice> inactiveDevices = pythonDeviceRepository.findInactiveDevices(cutoff);

        for (PythonDevice device : inactiveDevices) {
            logger.info("🧹 Cleaning up inactive Python device: {}", device.getDeviceId());
            device.setStatus("inactive");
            pythonDeviceRepository.save(device);
        }
    }

    // Statistics
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();

        long totalDevices = pythonDeviceRepository.count();
        long activeDevices = pythonDeviceRepository.findAll().stream()
                .filter(d -> "active".equals(d.getStatus()))
                .count();

        stats.put("totalDevices", totalDevices);
        stats.put("activeDevices", activeDevices);
        stats.put("totalLogs", pythonLogRepository.count());
        stats.put("totalUrlData", pythonUrlDataRepository.count());
        stats.put("totalAppUsage", pythonAppUsageRepository.count());
        stats.put("totalCertificates", pythonCertificateRepository.count());

        return stats;
    }

/**
 * Get app usage for a specific device within a date range
 */
public List<PythonAppUsage> getAppUsageByDeviceAndDateRange(String deviceId, 
                                                           LocalDateTime startDate, 
                                                           LocalDateTime endDate) {
    try {
        return pythonAppUsageRepository.findByDeviceIdAndTimestampBetween(deviceId, startDate, endDate);
    } catch (Exception e) {
        logger.error("Error getting app usage by date range for device {}: {}", deviceId, e.getMessage());
        return new ArrayList<>();
    }
}

/**
 * Get daily app usage summary for a device
 */
public Map<String, Object> getDailyAppUsage(String deviceId, LocalDate date) {
    Map<String, Object> result = new HashMap<>();
    
    try {
        // Set date boundaries for the day
        LocalDateTime startOfDay = date.atStartOfDay();
        LocalDateTime endOfDay = date.plusDays(1).atStartOfDay();
        
        // Get all app usage for the day
        List<PythonAppUsage> dailyUsage = getAppUsageByDeviceAndDateRange(deviceId, startOfDay, endOfDay);
        
        if (dailyUsage.isEmpty()) {
            result.put("dailyUsage", 0.0);
            result.put("categoryBreakdown", new HashMap<>());
            result.put("sessionCount", 0);
            result.put("latestApp", null);
            result.put("latestSessionDuration", 0.0);
            return result;
        }
        
        // Get the latest record for the day
        PythonAppUsage latestUsage = dailyUsage.stream()
            .findFirst() // Already sorted by timestamp desc
            .orElse(dailyUsage.get(0));
        
        // Calculate daily total - use the latest activeUsageTime
        // This assumes activeUsageTime in each record represents total for that day
        double dailyTotal = latestUsage.getActiveUsageTime() != null ? latestUsage.getActiveUsageTime() : 0.0;
        
        // Calculate category breakdown for the day
        Map<String, Double> categoryBreakdown = new HashMap<>();
        for (PythonAppUsage usage : dailyUsage) {
            Map<String, Object> breakdown = usage.getCategoryBreakdown();
            if (breakdown != null) {
                breakdown.forEach((category, timeObj) -> {
                    if (timeObj instanceof Number) {
                        double time = ((Number) timeObj).doubleValue();
                        categoryBreakdown.put(category,
                            categoryBreakdown.getOrDefault(category, 0.0) + time);
                    }
                });
            }
        }
        
        // Get top apps for the day
        List<Map<String, Object>> topApps = new ArrayList<>();
        if (!dailyUsage.isEmpty()) {
            // Use top apps from the latest record
            List<Map<String, Object>> latestTopApps = latestUsage.getTopApps();
            if (latestTopApps != null && !latestTopApps.isEmpty()) {
                topApps = latestTopApps;
            }
        }
        
        result.put("deviceId", deviceId);
        result.put("date", date.toString());
        result.put("dailyUsage", dailyTotal);
        result.put("categoryBreakdown", categoryBreakdown);
        result.put("topApps", topApps);
        result.put("sessionCount", dailyUsage.size());
        result.put("latestApp", latestUsage.getCurrentApp());
        result.put("latestSessionDuration", latestUsage.getCurrentSessionDuration() != null ? 
            latestUsage.getCurrentSessionDuration() : 0.0);
        result.put("totalAppsTracked", latestUsage.getTotalAppsTracked() != null ? 
            latestUsage.getTotalAppsTracked() : 0);
        result.put("totalTimeTracked", latestUsage.getTotalTimeTracked() != null ? 
            latestUsage.getTotalTimeTracked() : 0.0);
        
    } catch (Exception e) {
        logger.error("Error calculating daily app usage for device {}: {}", deviceId, e.getMessage());
        result.put("error", e.getMessage());
        result.put("dailyUsage", 0.0);
        result.put("categoryBreakdown", new HashMap<>());
    }
    
    return result;
}
}