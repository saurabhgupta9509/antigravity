package com.ma.dlp.controller;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ma.dlp.dto.ApiResponse;
import com.ma.dlp.dto.AppUsageRequest;
import com.ma.dlp.dto.BlockedUrlRequest;
import com.ma.dlp.dto.DeviceRegisterRequest;
import com.ma.dlp.dto.DeviceRegisterResponse;
import com.ma.dlp.dto.HeartbeatRequest;
import com.ma.dlp.dto.PartialAccessRequest;
import com.ma.dlp.dto.PythonLogRequest;
import com.ma.dlp.dto.ShutdownRequest;
import com.ma.dlp.dto.UrlMonitoringRequest;
import com.ma.dlp.model.BlockedUrlEntity;
import com.ma.dlp.model.PartialAccessEntity;
import com.ma.dlp.service.BlockedUrlService;
import com.ma.dlp.service.CertificateGenerationService;
import com.ma.dlp.service.PartialAccessService;
import com.ma.dlp.service.PythonClientService;
//
@RestController
@RequestMapping("/api/python-client")
public class PythonClientController {
   private final CertificateGenerationService certificateGenerationService;
   private final BlockedUrlService blockedUrlService;
   private final ObjectMapper objectMapper;

   private static final Logger logger = LoggerFactory.getLogger(PythonClientController.class);

   @Autowired
   private PythonClientService pythonClientService;

   public PythonClientController(
       PythonClientService pythonClientService,
       CertificateGenerationService certificateGenerationService,
       BlockedUrlService blockedUrlService,
       ObjectMapper objectMapper) {  // Add this parameter
   this.pythonClientService = pythonClientService;
   this.certificateGenerationService = certificateGenerationService;
   this.blockedUrlService = blockedUrlService;
   this.objectMapper = objectMapper;  // Initialize it
}

   // ============ BLOCKED URLS ENDPOINTS ============

   /**
    * Get blocked URLs for a specific device
    */
   @GetMapping("/devices/{deviceId}/blocked-urls")
   public ResponseEntity<ApiResponse<List<String>>> getBlockedUrlsForDevice(
           @PathVariable String deviceId) {
       try {
           // Get device to get userId
           var deviceOpt = pythonClientService.getDeviceById(deviceId);
           if (deviceOpt.isEmpty()) {
               return ResponseEntity.ok(new ApiResponse<>(false, "Device not found", List.of()));
           }

           var device = deviceOpt.get();
           List<String> blockedUrls = blockedUrlService.getBlockedUrlPatterns(deviceId, device.getUserId());

           logger.info("🚫 Blocked URLs for device {}: {} patterns", deviceId, blockedUrls.size());
           return ResponseEntity.ok(new ApiResponse<>(true, "Blocked URLs retrieved", blockedUrls));

       } catch (Exception e) {
           logger.error("❌ Failed to get blocked URLs: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get blocked URLs"));
       }
   }

   /**
    * Get all blocked URLs (admin view)
    */
   @GetMapping("/blocked-urls")
   public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getAllBlockedUrls() {
       try {
           List<Map<String, Object>> blockedUrls = blockedUrlService.getAllBlockedUrls().stream()
                   .map(entity -> {
                       Map<String, Object> map = new HashMap<>();
                       map.put("id", entity.getId());
                       map.put("urlPattern", entity.getUrlPattern());
                       map.put("domain", entity.getDomain());
                       map.put("reason", entity.getReason());
                       map.put("category", entity.getCategory());
                       map.put("active", entity.isActive());
                       map.put("global", entity.isGlobal());
                       map.put("deviceId", entity.getDeviceId());
                       map.put("userId", entity.getUserId());
                       map.put("addedBy", entity.getAddedBy());
                       map.put("hitCount", entity.getHitCount());
                       map.put("createdAt", entity.getCreatedAt());
                       map.put("updatedAt", entity.getUpdatedAt());
                       return map;
                   })
                   .collect(Collectors.toList());

           return ResponseEntity.ok(new ApiResponse<>(true, "Blocked URLs retrieved", blockedUrls));

       } catch (Exception e) {
           logger.error("❌ Failed to get blocked URLs: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get blocked URLs"));
       }
   }

   /**
    * Add blocked URL (admin only)
    */
   @PostMapping("/blocked-urls")
   public ResponseEntity<ApiResponse<Map<String, Object>>> addBlockedUrl(
           @RequestBody BlockedUrlRequest request) {
       try {
           String addedBy = "admin"; // Get from authentication in production
           BlockedUrlEntity entity = blockedUrlService.addBlockedUrl(request, addedBy);

           Map<String, Object> response = new HashMap<>();
           response.put("id", entity.getId());
           response.put("urlPattern", entity.getUrlPattern());
           response.put("domain", entity.getDomain());
           response.put("message", "Blocked URL added successfully");

           logger.info("✅ Blocked URL added: {}", entity.getUrlPattern());
           return ResponseEntity.ok(new ApiResponse<>(true, "Blocked URL added", response));

       } catch (Exception e) {
           logger.error("❌ Failed to add blocked URL: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to add blocked URL: " + e.getMessage()));
       }
   }

   /**
    * Add multiple blocked URLs (admin only)
    */
   @PostMapping("/blocked-urls/bulk")
   public ResponseEntity<ApiResponse<Map<String, Object>>> addBulkBlockedUrls(
           @RequestBody BlockedUrlRequest request) {
       try {
           if (request.getBlockedUrls() == null || request.getBlockedUrls().isEmpty()) {
               return ResponseEntity.badRequest()
                       .body(new ApiResponse<>(false, "No URLs provided"));
           }

           String addedBy = "admin"; // Get from authentication in production
           List<BlockedUrlEntity> entities = blockedUrlService.addBlockedUrls(request.getBlockedUrls(), addedBy);

           Map<String, Object> response = new HashMap<>();
           response.put("addedCount", entities.size());
           response.put("urls", entities.stream()
                   .map(e -> Map.of(
                       "id", e.getId(),
                       "urlPattern", e.getUrlPattern(),
                       "domain", e.getDomain()
                   ))
                   .collect(Collectors.toList()));

           logger.info("✅ Added {} blocked URLs in bulk", entities.size());
           return ResponseEntity.ok(new ApiResponse<>(true, "Blocked URLs added in bulk", response));

       } catch (Exception e) {
           logger.error("❌ Failed to add bulk blocked URLs: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to add blocked URLs: " + e.getMessage()));
       }
   }

   /**
    * Update blocked URL (admin only)
    */
   @PutMapping("/blocked-urls/{id}")
   public ResponseEntity<ApiResponse<Map<String, Object>>> updateBlockedUrl(
           @PathVariable Long id,
           @RequestBody BlockedUrlRequest request) {
       try {
           BlockedUrlEntity entity = blockedUrlService.updateBlockedUrl(id, request);

           Map<String, Object> response = new HashMap<>();
           response.put("id", entity.getId());
           response.put("urlPattern", entity.getUrlPattern());
           response.put("domain", entity.getDomain());
           response.put("message", "Blocked URL updated successfully");

           logger.info("✅ Blocked URL updated: {}", entity.getUrlPattern());
           return ResponseEntity.ok(new ApiResponse<>(true, "Blocked URL updated", response));

       } catch (Exception e) {
           logger.error("❌ Failed to update blocked URL: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to update blocked URL: " + e.getMessage()));
       }
   }

   /**
    * Delete blocked URL (admin only)
    */
   @DeleteMapping("/blocked-urls/{id}")
   public ResponseEntity<ApiResponse<String>> deleteBlockedUrl(@PathVariable Long id) {
       try {
           blockedUrlService.deleteBlockedUrl(id);
           return ResponseEntity.ok(new ApiResponse<>(true, "Blocked URL deleted"));

       } catch (Exception e) {
           logger.error("❌ Failed to delete blocked URL: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to delete blocked URL: " + e.getMessage()));
       }
   }

   /**
    * Delete blocked URLs by patterns (admin only)
    */
   @DeleteMapping("/blocked-urls")
   public ResponseEntity<ApiResponse<Map<String, Object>>> deleteBlockedUrls(
           @RequestBody BlockedUrlRequest request) {
       try {
           if (request.getDeletePatterns() == null || request.getDeletePatterns().isEmpty()) {
               return ResponseEntity.badRequest()
                       .body(new ApiResponse<>(false, "No patterns provided"));
           }

           int deletedCount = blockedUrlService.deleteByPatterns(request.getDeletePatterns());

           Map<String, Object> response = new HashMap<>();
           response.put("deletedCount", deletedCount);
           response.put("message", deletedCount + " blocked URL(s) deleted");

           return ResponseEntity.ok(new ApiResponse<>(true, "Blocked URLs deleted", response));

       } catch (Exception e) {
           logger.error("❌ Failed to delete blocked URLs: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to delete blocked URLs: " + e.getMessage()));
       }
   }

   /**
    * Toggle blocked URL status (admin only)
    */
   @PatchMapping("/blocked-urls/{id}/toggle")
   public ResponseEntity<ApiResponse<Map<String, Object>>> toggleBlockedUrl(
           @PathVariable Long id,
           @RequestParam boolean active) {
       try {
           BlockedUrlEntity entity = blockedUrlService.toggleBlockedUrl(id, active);

           Map<String, Object> response = new HashMap<>();
           response.put("id", entity.getId());
           response.put("urlPattern", entity.getUrlPattern());
           response.put("active", entity.isActive());
           response.put("message", "Blocked URL " + (active ? "activated" : "deactivated"));

           logger.info("🔄 Blocked URL toggled: {} -> {}", entity.getUrlPattern(), active ? "active" : "inactive");
           return ResponseEntity.ok(new ApiResponse<>(true, "Blocked URL status updated", response));

       } catch (Exception e) {
           logger.error("❌ Failed to toggle blocked URL: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to toggle blocked URL: " + e.getMessage()));
       }
   }

   /**
    * Search blocked URLs
    */
   @GetMapping("/blocked-urls/search")
   public ResponseEntity<ApiResponse<List<Map<String, Object>>>> searchBlockedUrls(
           @RequestParam String keyword) {
       try {
           List<BlockedUrlEntity> entities = blockedUrlService.searchUrls(keyword);

           List<Map<String, Object>> blockedUrls = entities.stream()
                   .map(entity -> {
                       Map<String, Object> map = new HashMap<>();
                       map.put("id", entity.getId());
                       map.put("urlPattern", entity.getUrlPattern());
                       map.put("domain", entity.getDomain());
                       map.put("reason", entity.getReason());
                       map.put("category", entity.getCategory());
                       map.put("active", entity.isActive());
                       map.put("global", entity.isGlobal());
                       map.put("deviceId", entity.getDeviceId());
                       map.put("userId", entity.getUserId());
                       map.put("addedBy", entity.getAddedBy());
                       map.put("hitCount", entity.getHitCount());
                       map.put("createdAt", entity.getCreatedAt());
                       map.put("updatedAt", entity.getUpdatedAt());
                       return map;
                   })
                   .collect(Collectors.toList());

           return ResponseEntity.ok(new ApiResponse<>(true, "Search results", blockedUrls));

       } catch (Exception e) {
           logger.error("❌ Failed to search blocked URLs: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to search blocked URLs"));
       }
   }

   /**
    * Get blocked URL statistics
    */
   @GetMapping("/blocked-urls/stats")
   public ResponseEntity<ApiResponse<Map<String, Object>>> getBlockedUrlStats() {
       try {
           Map<String, Object> stats = blockedUrlService.getStatistics();
           return ResponseEntity.ok(new ApiResponse<>(true, "Blocked URL statistics", stats));

       } catch (Exception e) {
           logger.error("❌ Failed to get blocked URL stats: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get statistics"));
       }
   }

   /**
    * Get most blocked URLs
    */
   @GetMapping("/blocked-urls/most-blocked")
   public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getMostBlockedUrls(
           @RequestParam(defaultValue = "10") int limit) {
       try {
           List<Map<String, Object>> mostBlocked = blockedUrlService.getMostBlockedUrls(limit);
           return ResponseEntity.ok(new ApiResponse<>(true, "Most blocked URLs", mostBlocked));

       } catch (Exception e) {
           logger.error("❌ Failed to get most blocked URLs: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get most blocked URLs"));
       }
   }

   /**
    * Get blocked URLs by category
    */
   @GetMapping("/blocked-urls/category/{category}")
   public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getBlockedUrlsByCategory(
           @PathVariable String category) {
       try {
           List<BlockedUrlEntity> entities = blockedUrlService.getUrlsByCategory(category);

           List<Map<String, Object>> blockedUrls = entities.stream()
                   .map(entity -> {
                       Map<String, Object> map = new HashMap<>();
                       map.put("id", entity.getId());
                       map.put("urlPattern", entity.getUrlPattern());
                       map.put("domain", entity.getDomain());
                       map.put("reason", entity.getReason());
                       map.put("category", entity.getCategory());
                       map.put("active", entity.isActive());
                       map.put("global", entity.isGlobal());
                       map.put("deviceId", entity.getDeviceId());
                       map.put("userId", entity.getUserId());
                       map.put("addedBy", entity.getAddedBy());
                       map.put("hitCount", entity.getHitCount());
                       map.put("createdAt", entity.getCreatedAt());
                       map.put("updatedAt", entity.getUpdatedAt());
                       return map;
                   })
                   .collect(Collectors.toList());

           return ResponseEntity.ok(new ApiResponse<>(true, "Blocked URLs by category", blockedUrls));

       } catch (Exception e) {
           logger.error("❌ Failed to get blocked URLs by category: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get blocked URLs by category"));
       }
   }

   // ============ ORIGINAL ENDPOINTS (Keep all existing endpoints) ============

   /**
    * Device Registration for Python Client
    */
   @PostMapping("/devices/register")
   public ResponseEntity<ApiResponse<DeviceRegisterResponse>> registerPythonDevice(
           @RequestBody DeviceRegisterRequest request) {
       try {
           logger.info("📱 Python Device Registration: {}", request.getDeviceId());

           Map<String, Object> deviceData = new HashMap<>();
           deviceData.put("deviceId", request.getDeviceId());
           deviceData.put("userId", request.getUserId());
           deviceData.put("deviceName", request.getDeviceName());
           deviceData.put("platform", request.getPlatform());
           deviceData.put("monitorVersion", request.getMonitorVersion());

           pythonClientService.registerDevice(deviceData);

           DeviceRegisterResponse response = new DeviceRegisterResponse();
           response.setId(request.getDeviceId());
           response.setStatus("registered");
           response.setRegisteredAt(LocalDateTime.now().toString());

           logger.info("✅ Python device registered successfully: {}", request.getDeviceId());

           return ResponseEntity.ok(new ApiResponse<>(true, "Python device registered", response));

       } catch (Exception e) {
           logger.error("❌ Python device registration failed: {}", e.getMessage(), e);
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Registration failed: " + e.getMessage()));
       }
   }

   /**
    * Heartbeat endpoint for Python client
    */
   @PostMapping("/devices/{deviceId}/heartbeat")
   public ResponseEntity<ApiResponse<String>> pythonHeartbeat(
           @PathVariable String deviceId,
          @RequestBody(required = false) HeartbeatRequest request) {

       try {
           pythonClientService.updateHeartbeat(deviceId);
           logger.debug("💓 Python device heartbeat: {}", deviceId);
           return ResponseEntity.ok(new ApiResponse<>(true, "Heartbeat received"));

       } catch (Exception e) {
           logger.error("❌ Python heartbeat failed: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Heartbeat failed"));
       }
   }

   /**
    * Log upload endpoint for Python client
    */
   @PostMapping("/devices/{deviceId}/logs")
   public ResponseEntity<ApiResponse<String>> uploadPythonLogs(
           @PathVariable String deviceId,
           @RequestBody PythonLogRequest request) {

       try {
           Map<String, Object> logData = new HashMap<>();
           logData.put("deviceId", deviceId);
           logData.put("logType", request.getLogType());
           logData.put("logContent", request.getLogContent());
           logData.put("fileSize", request.getFileSize());

           pythonClientService.saveLog(logData);

           logger.info("📝 Python log uploaded - Device: {}, Type: {}",
                   deviceId, request.getLogType());

           return ResponseEntity.ok(new ApiResponse<>(true, "Logs uploaded successfully"));

       } catch (Exception e) {
           logger.error("❌ Python log upload failed: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Log upload failed"));
       }
   }

   /**
    * Get all logs
    */
   @GetMapping("/logs")
   public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getAllLogs() {
       try {
           List<Map<String, Object>> logs = pythonClientService.getAllDevices().stream()
                   .flatMap(device -> pythonClientService.getDeviceLogs(device.getDeviceId()).stream())
                   .map(log -> {
                       Map<String, Object> logMap = new HashMap<>();
                       logMap.put("id", log.getId());
                       logMap.put("deviceId", log.getDeviceId());
                       logMap.put("logType", log.getLogType());
                       logMap.put("logContent", log.getLogContent());
                       logMap.put("timestamp", log.getTimestamp());
                       logMap.put("fileSize", log.getFileSize());
                       return logMap;
                   })
                   .sorted((a, b) -> ((LocalDateTime) b.get("timestamp"))
                           .compareTo((LocalDateTime) a.get("timestamp")))
                   .limit(100)
                   .collect(Collectors.toList());

           return ResponseEntity.ok(new ApiResponse<>(true, "Logs retrieved", logs));
       } catch (Exception e) {
           logger.error("❌ Failed to get logs: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get logs"));
       }
   }

   /**
    * Get logs for specific device
    */
   @GetMapping("/devices/{deviceId}/logs")
   public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getDeviceLogs(@PathVariable String deviceId) {
       try {
           List<Map<String, Object>> logs = pythonClientService.getDeviceLogs(deviceId).stream()
                   .map(log -> {
                       Map<String, Object> logMap = new HashMap<>();
                       logMap.put("id", log.getId());
                       logMap.put("deviceId", log.getDeviceId());
                       logMap.put("logType", log.getLogType());
                       logMap.put("logContent", log.getLogContent());
                       logMap.put("timestamp", log.getTimestamp());
                       logMap.put("fileSize", log.getFileSize());
                       return logMap;
                   })
                   .collect(Collectors.toList());

           return ResponseEntity.ok(new ApiResponse<>(true, "Device logs retrieved", logs));
       } catch (Exception e) {
           logger.error("❌ Failed to get device logs: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get device logs"));
       }
   }

   /**
    * URL monitoring data upload
    */
   @PostMapping("/devices/{deviceId}/urls")
   public ResponseEntity<ApiResponse<String>> uploadPythonUrls(
           @PathVariable String deviceId,
           @RequestBody UrlMonitoringRequest request) {

       try {
           Map<String, Object> urlData = new HashMap<>();
           urlData.put("deviceId", deviceId);
           urlData.put("urls", request.getUrls());
           urlData.put("blockedCount", request.getBlockedCount());
           urlData.put("suspiciousCount", request.getSuspiciousCount());
           urlData.put("totalVisits", request.getTotalVisits());

           pythonClientService.saveUrlData(urlData);

           logger.info("🌐 Python URL data - Device: {}, URLs: {}, Blocked: {}",
                   deviceId, request.getUrls().size(), request.getBlockedCount());

           return ResponseEntity.ok(new ApiResponse<>(true, "URL data uploaded"));

       } catch (Exception e) {
           logger.error("❌ Python URL upload failed: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "URL upload failed"));
       }
   }

   /**
    * Get all URL data
    */
   @GetMapping("/urls")
   public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getAllUrls() {
       try {
           List<Map<String, Object>> urls = pythonClientService.getAllDevices().stream()
                   .flatMap(device -> pythonClientService.getDeviceUrlHistory(device.getDeviceId()).stream())
                   .map(url -> {
                       Map<String, Object> urlMap = new HashMap<>();
                       urlMap.put("id", url.getId());
                       urlMap.put("deviceId", url.getDeviceId());
                       urlMap.put("urls", url.getUrls());
                       urlMap.put("blockedCount", url.getBlockedCount());
                       urlMap.put("suspiciousCount", url.getSuspiciousCount());
                       urlMap.put("totalVisits", url.getTotalVisits());
                       urlMap.put("timestamp", url.getTimestamp());
                       return urlMap;
                   })
                   .sorted((a, b) -> ((LocalDateTime) b.get("timestamp"))
                           .compareTo((LocalDateTime) a.get("timestamp")))
                   .limit(100)
                   .collect(Collectors.toList());

           return ResponseEntity.ok(new ApiResponse<>(true, "URL data retrieved", urls));
       } catch (Exception e) {
           logger.error("❌ Failed to get URL data: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get URL data"));
       }
   }

   /**
    * Get URL data for specific device
    */
   @GetMapping("/devices/{deviceId}/urls")
   public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getDeviceUrls(@PathVariable String deviceId) {
       try {
           List<Map<String, Object>> urls = pythonClientService.getDeviceUrlHistory(deviceId).stream()
                   .map(url -> {
                       Map<String, Object> urlMap = new HashMap<>();
                       urlMap.put("id", url.getId());
                       urlMap.put("deviceId", url.getDeviceId());
                       urlMap.put("urls", url.getUrls());
                       urlMap.put("blockedCount", url.getBlockedCount());
                       urlMap.put("suspiciousCount", url.getSuspiciousCount());
                       urlMap.put("totalVisits", url.getTotalVisits());
                       urlMap.put("timestamp", url.getTimestamp());
                       return urlMap;
                   })
                   .collect(Collectors.toList());

           return ResponseEntity.ok(new ApiResponse<>(true, "Device URL data retrieved", urls));
       } catch (Exception e) {
           logger.error("❌ Failed to get device URL data: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get device URL data"));
       }
   }

   /**
    * App usage data upload
    */
   @PostMapping("/devices/{deviceId}/app-usage")
   public ResponseEntity<ApiResponse<String>> uploadPythonAppUsage(
           @PathVariable String deviceId,
           @RequestBody AppUsageRequest request) {

       try {
           logger.info("📱 ====== APP USAGE CONTROLLER START ======");
           logger.info("📱 Active Usage Time: {}", request.getActiveUsageTime());

           Map<String, Object> appData = new HashMap<>();
           appData.put("deviceId", deviceId);
           appData.put("currentApp", request.getCurrentApp());
           appData.put("currentSessionDuration", request.getCurrentSessionDuration());
           appData.put("totalAppsTracked", request.getTotalAppsTracked());
           appData.put("totalTimeTracked", request.getTotalTimeTracked());
           appData.put("activeUsageTime", request.getActiveUsageTime());
           appData.put("topApps", request.getTopApps());
           appData.put("categoryBreakdown", request.getCategoryBreakdown());

           pythonClientService.saveAppUsage(appData);

           logger.info("📱 Active Usage Time (for dashboard): {}s", request.getActiveUsageTime());
           logger.info("📱 ====== APP USAGE CONTROLLER END ======");

           return ResponseEntity.ok(new ApiResponse<>(true, "App usage data uploaded"));

       } catch (Exception e) {
           logger.error("❌ Python app usage upload failed: {}", e.getMessage(), e);
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "App usage upload failed"));
       }
   }

   /**
    * Get all app usage data
    */
   @GetMapping("/app-usage")
   public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getAllAppUsage() {
       try {
           List<Map<String, Object>> appUsage = pythonClientService.getAllDevices().stream()
                   .flatMap(device -> pythonClientService.getDeviceAppUsageHistory(device.getDeviceId()).stream())
                   .map(app -> {
                       Map<String, Object> appMap = new HashMap<>();
                       appMap.put("id", app.getId());
                       appMap.put("deviceId", app.getDeviceId());
                       appMap.put("currentApp", app.getCurrentApp());
                       appMap.put("currentSessionDuration", app.getCurrentSessionDuration());
                       appMap.put("totalAppsTracked", app.getTotalAppsTracked());
                       appMap.put("totalTimeTracked", app.getTotalTimeTracked());
                       appMap.put("activeUsageTime", app.getActiveUsageTime());
                       appMap.put("topApps", app.getTopApps());
                       appMap.put("categoryBreakdown", app.getCategoryBreakdown());
                       appMap.put("timestamp", app.getTimestamp());
                       return appMap;
                   })
                   .sorted((a, b) -> ((LocalDateTime) b.get("timestamp"))
                           .compareTo((LocalDateTime) a.get("timestamp")))
                   .limit(100)
                   .collect(Collectors.toList());

           return ResponseEntity.ok(new ApiResponse<>(true, "App usage data retrieved", appUsage));
       } catch (Exception e) {
           logger.error("❌ Failed to get app usage data: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get app usage data"));
       }
   }

   /**
    * Get app usage for specific device
    */
   @GetMapping("/devices/{deviceId}/app-usage")
   public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getDeviceAppUsage(@PathVariable String deviceId) {
       try {
           List<Map<String, Object>> appUsage = pythonClientService.getDeviceAppUsageHistory(deviceId).stream()
                   .map(app -> {
                       Map<String, Object> appMap = new HashMap<>();
                       appMap.put("id", app.getId());
                       appMap.put("deviceId", app.getDeviceId());
                       appMap.put("currentApp", app.getCurrentApp());
                       appMap.put("currentSessionDuration", app.getCurrentSessionDuration());
                       appMap.put("totalAppsTracked", app.getTotalAppsTracked());
                       appMap.put("totalTimeTracked", app.getTotalTimeTracked());
                       appMap.put("activeUsageTime", app.getActiveUsageTime());
                       appMap.put("topApps", app.getTopApps());
                       appMap.put("categoryBreakdown", app.getCategoryBreakdown());
                       appMap.put("timestamp", app.getTimestamp());
                       return appMap;
                   })
                   .collect(Collectors.toList());

           return ResponseEntity.ok(new ApiResponse<>(true, "Device app usage retrieved", appUsage));
       } catch (Exception e) {
           logger.error("❌ Failed to get device app usage: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get device app usage"));
       }
   }

   /**
    * Get all certificates
    */
   @GetMapping("/certificates")
   public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getAllCertificates() {
       try {
           List<Map<String, Object>> certificates = pythonClientService.getAllDevices().stream()
                   .flatMap(device -> pythonClientService.getDeviceCertificates(device.getDeviceId()).stream())
                   .map(cert -> {
                       Map<String, Object> certMap = new HashMap<>();
                       certMap.put("id", cert.getId());
                       certMap.put("deviceId", cert.getDeviceId());
                       certMap.put("certificateId", cert.getCertificateId());
                       certMap.put("uploadedAt", cert.getUploadedAt());
                       certMap.put("generated", cert.getGenerated());
                       certMap.put("validUntil", cert.getValidUntil());
                       certMap.put("issuer", cert.getIssuer());
                       certMap.put("recipient", cert.getRecipient());
                       certMap.put("device", cert.getDevice());
                       certMap.put("securityMetrics", cert.getSecurityMetrics());
                       certMap.put("detailedAnalysis", cert.getDetailedAnalysis());
                       certMap.put("recommendations", cert.getRecommendations());
                       certMap.put("signature", cert.getSignature());
                       return certMap;
                   })
                   .sorted((a, b) -> ((LocalDateTime) b.get("uploadedAt"))
                           .compareTo((LocalDateTime) a.get("uploadedAt")))
                   .limit(50)
                   .collect(Collectors.toList());

           return ResponseEntity.ok(new ApiResponse<>(true, "Certificates retrieved", certificates));
       } catch (Exception e) {
           logger.error("❌ Failed to get certificates: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get certificates"));
       }
   }

   @PostMapping("/certificates/generate/{deviceId}")
   public ResponseEntity<ApiResponse<String>> generateCertificateForDevice(
           @PathVariable String deviceId) {
       try {
           certificateGenerationService.generateCertificateForDeviceNow(deviceId);
           return ResponseEntity.ok(new ApiResponse<>(true, "Certificate generation triggered for device: " + deviceId));
       } catch (Exception e) {
           logger.error("❌ Failed to generate certificate: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Certificate generation failed: " + e.getMessage()));
       }
   }

   @PostMapping("/certificates/generate-all")
   public ResponseEntity<ApiResponse<String>> generateCertificatesForAllDevices() {
       try {
           certificateGenerationService.generateCertificatesFromRecentUrls();
           return ResponseEntity.ok(new ApiResponse<>(true, "Certificate generation triggered for all devices"));
       } catch (Exception e) {
           logger.error("❌ Failed to generate certificates: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Certificate generation failed: " + e.getMessage()));
       }
   }

   /**
    * Get certificates for specific device
    */
   @GetMapping("/devices/{deviceId}/certificates")
   public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getDeviceCertificates(@PathVariable String deviceId) {
       try {
           List<Map<String, Object>> certificates = pythonClientService.getDeviceCertificates(deviceId).stream()
                   .map(cert -> {
                       Map<String, Object> certMap = new HashMap<>();
                       certMap.put("id", cert.getId());
                       certMap.put("deviceId", cert.getDeviceId());
                       certMap.put("certificateId", cert.getCertificateId());
                       certMap.put("uploadedAt", cert.getUploadedAt());
                       certMap.put("generated", cert.getGenerated());
                       certMap.put("validUntil", cert.getValidUntil());
                       certMap.put("issuer", cert.getIssuer());
                       certMap.put("recipient", cert.getRecipient());
                       certMap.put("device", cert.getDevice());
                       certMap.put("securityMetrics", cert.getSecurityMetrics());
                       certMap.put("detailedAnalysis", cert.getDetailedAnalysis());
                       certMap.put("recommendations", cert.getRecommendations());
                       certMap.put("signature", cert.getSignature());
                       return certMap;
                   })
                   .collect(Collectors.toList());

           return ResponseEntity.ok(new ApiResponse<>(true, "Device certificates retrieved", certificates));
       } catch (Exception e) {
           logger.error("❌ Failed to get device certificates: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get device certificates"));
       }
   }

   /**
    * Shutdown notification
    */
   @PostMapping("/devices/{deviceId}/shutdown")
   public ResponseEntity<ApiResponse<String>> pythonShutdown(
           @PathVariable String deviceId,
           @RequestBody ShutdownRequest request) {

       try {
           pythonClientService.handleShutdown(deviceId);

           logger.info("🛑 Python device shutdown - Device: {}, Reason: {}",
                   deviceId, request.getReason());

           return ResponseEntity.ok(new ApiResponse<>(true, "Shutdown notification received"));

       } catch (Exception e) {
           logger.error("❌ Python shutdown notification failed: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Shutdown notification failed"));
       }
   }

   /**
    * Get all Python devices (for admin panel)
    */
   @GetMapping("/devices")
   public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getAllPythonDevices() {
       try {
           List<Map<String, Object>> devices = pythonClientService.getAllDevices().stream()
                   .map(device -> {
                       Map<String, Object> deviceMap = new HashMap<>();
                       deviceMap.put("id", device.getId());
                       deviceMap.put("deviceId", device.getDeviceId());
                       deviceMap.put("deviceName", device.getDeviceName());
                       deviceMap.put("platform", device.getPlatform());
                       deviceMap.put("status", device.getStatus());
                       deviceMap.put("lastHeartbeat", device.getLastHeartbeat());
                       deviceMap.put("firstSeen", device.getFirstSeen());
                       deviceMap.put("monitorVersion", device.getMonitorVersion());
                       deviceMap.put("userId", device.getUserId());
                       return deviceMap;
                   })
                   .collect(Collectors.toList());

           return ResponseEntity.ok(new ApiResponse<>(true, "Python devices retrieved", devices));
       } catch (Exception e) {
           logger.error("❌ Failed to get Python devices: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get devices"));
       }
   }

   /**
    * Get specific device
    */
   @GetMapping("/devices/{deviceId}")
   public ResponseEntity<ApiResponse<Map<String, Object>>> getPythonDevice(@PathVariable String deviceId) {
       try {
           var deviceOpt = pythonClientService.getDeviceById(deviceId);
           if (deviceOpt.isPresent()) {
               var device = deviceOpt.get();
               Map<String, Object> deviceMap = new HashMap<>();
               deviceMap.put("id", device.getId());
               deviceMap.put("deviceId", device.getDeviceId());
               deviceMap.put("deviceName", device.getDeviceName());
               deviceMap.put("platform", device.getPlatform());
               deviceMap.put("status", device.getStatus());
               deviceMap.put("lastHeartbeat", device.getLastHeartbeat());
               deviceMap.put("firstSeen", device.getFirstSeen());
               deviceMap.put("monitorVersion", device.getMonitorVersion());
               deviceMap.put("userId", device.getUserId());
               deviceMap.put("deviceInfo", device.getDeviceInfo());
               deviceMap.put("lastSeen", device.getLastSeen());
               return ResponseEntity.ok(new ApiResponse<>(true, "Device retrieved", deviceMap));
           } else {
               return ResponseEntity.ok(new ApiResponse<>(false, "Device not found"));
           }
       } catch (Exception e) {
           logger.error("❌ Failed to get device: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get device"));
       }
   }

   /**
    * Get Python device statistics
    */
   @GetMapping("/stats")
   public ResponseEntity<ApiResponse<Map<String, Object>>> getPythonStats() {
       try {
           Map<String, Object> stats = pythonClientService.getStatistics();
           return ResponseEntity.ok(new ApiResponse<>(true, "Python statistics", stats));
       } catch (Exception e) {
           logger.error("❌ Failed to get Python stats: {}", e.getMessage());
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "Failed to get statistics"));
       }
   }

   // ============ PARTIAL ACCESS ENDPOINTS ============

@Autowired
private PartialAccessService partialAccessService;

/**
* Get partial access configuration for a specific device
*/
@GetMapping("/devices/{deviceId}/partial-access")
public ResponseEntity<ApiResponse<Map<String, Object>>> getPartialAccessForDevice(
       @PathVariable String deviceId) {
   try {
       // Get device to get userId
       var deviceOpt = pythonClientService.getDeviceById(deviceId);
       if (deviceOpt.isEmpty()) {
           return ResponseEntity.ok(new ApiResponse<>(false, "Device not found", Map.of()));
       }

       var device = deviceOpt.get();
       Map<String, Object> config = partialAccessService.getPartialAccessConfig(deviceId, device.getUserId());

       logger.info("🔓 Partial access config for device {}: {} sites",
           deviceId, ((List<?>) config.get("partialAccessSites")).size());
       return ResponseEntity.ok(new ApiResponse<>(true, "Partial access config retrieved", config));

   } catch (Exception e) {
       logger.error("❌ Failed to get partial access config: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to get partial access config"));
   }
}

/**
* Get all partial access sites (admin view)
*/
@GetMapping("/partial-access")
public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getAllPartialAccessSites() {
   try {
       List<Map<String, Object>> sites = partialAccessService.getAllPartialAccessSites().stream()
               .map(entity -> {
                   Map<String, Object> map = new HashMap<>();
                   map.put("id", entity.getId());
                   map.put("urlPattern", entity.getUrlPattern());
                   map.put("domain", entity.getDomain());
                   map.put("reason", entity.getReason());
                   map.put("category", entity.getCategory());
                   map.put("active", entity.isActive());
                   map.put("global", entity.isGlobal());
                   map.put("allowUpload", entity.isAllowUpload());
                   map.put("allowDownload", entity.isAllowDownload());
                   map.put("monitorMode", entity.getMonitorMode());
                   map.put("deviceId", entity.getDeviceId());
                   map.put("userId", entity.getUserId());
                   map.put("addedBy", entity.getAddedBy());
                   map.put("uploadAttempts", entity.getUploadAttempts());
                   map.put("downloadAttempts", entity.getDownloadAttempts());
                   map.put("createdAt", entity.getCreatedAt());
                   map.put("updatedAt", entity.getUpdatedAt());

                   // Parse restricted file types
                   try {
                       if (entity.getRestrictedFileTypes() != null && !entity.getRestrictedFileTypes().isEmpty()) {
                           List<String> fileTypes = objectMapper.readValue(
                               entity.getRestrictedFileTypes(),
                               new com.fasterxml.jackson.core.type.TypeReference<List<String>>() {}
                           );
                           map.put("restrictedFileTypes", fileTypes);
                       } else {
                           map.put("restrictedFileTypes", new ArrayList<>());
                       }
                   } catch (Exception e) {
                       map.put("restrictedFileTypes", new ArrayList<>());
                   }

                   return map;
               })
               .collect(Collectors.toList());

       return ResponseEntity.ok(new ApiResponse<>(true, "Partial access sites retrieved", sites));

   } catch (Exception e) {
       logger.error("❌ Failed to get partial access sites: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to get partial access sites"));
   }
}

/**
* Get partial access site by ID
*/
@GetMapping("/partial-access/{id}")
public ResponseEntity<ApiResponse<Map<String, Object>>> getPartialAccessSite(@PathVariable Long id) {
   try {
       var siteOpt = partialAccessService.getPartialAccessSiteById(id);
       if (siteOpt.isPresent()) {
           var entity = siteOpt.get();
           Map<String, Object> map = new HashMap<>();
           map.put("id", entity.getId());
           map.put("urlPattern", entity.getUrlPattern());
           map.put("domain", entity.getDomain());
           map.put("reason", entity.getReason());
           map.put("category", entity.getCategory());
           map.put("active", entity.isActive());
           map.put("global", entity.isGlobal());
           map.put("allowUpload", entity.isAllowUpload());
           map.put("allowDownload", entity.isAllowDownload());
           map.put("monitorMode", entity.getMonitorMode());
           map.put("deviceId", entity.getDeviceId());
           map.put("userId", entity.getUserId());
           map.put("addedBy", entity.getAddedBy());
           map.put("uploadAttempts", entity.getUploadAttempts());
           map.put("downloadAttempts", entity.getDownloadAttempts());
           map.put("createdAt", entity.getCreatedAt());
           map.put("updatedAt", entity.getUpdatedAt());

           // Parse restricted file types
           try {
               if (entity.getRestrictedFileTypes() != null && !entity.getRestrictedFileTypes().isEmpty()) {
                   List<String> fileTypes = objectMapper.readValue(
                       entity.getRestrictedFileTypes(),
                       new com.fasterxml.jackson.core.type.TypeReference<List<String>>() {}
                   );
                   map.put("restrictedFileTypes", fileTypes);
               } else {
                   map.put("restrictedFileTypes", new ArrayList<>());
               }
           } catch (Exception e) {
               map.put("restrictedFileTypes", new ArrayList<>());
           }

           return ResponseEntity.ok(new ApiResponse<>(true, "Partial access site retrieved", map));
       } else {
           return ResponseEntity.ok(new ApiResponse<>(false, "Partial access site not found"));
       }

   } catch (Exception e) {
       logger.error("❌ Failed to get partial access site: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to get partial access site"));
   }
}

/**
* Add partial access site (admin only)
*/
@PostMapping("/partial-access")
public ResponseEntity<ApiResponse<Map<String, Object>>> addPartialAccessSite(
       @RequestBody PartialAccessRequest request) {
   try {
       String addedBy = "admin"; // Get from authentication in production
       PartialAccessEntity entity = partialAccessService.addPartialAccessSite(request, addedBy);

       Map<String, Object> response = new HashMap<>();
       response.put("id", entity.getId());
       response.put("urlPattern", entity.getUrlPattern());
       response.put("domain", entity.getDomain());
       response.put("allowUpload", entity.isAllowUpload());
       response.put("allowDownload", entity.isAllowDownload());
       response.put("monitorMode", entity.getMonitorMode());
       response.put("message", "Partial access site added successfully");

       logger.info("✅ Partial access site added: {} (Upload: {}, Download: {})",
           entity.getUrlPattern(), entity.isAllowUpload(), entity.isAllowDownload());
       return ResponseEntity.ok(new ApiResponse<>(true, "Partial access site added", response));

   } catch (Exception e) {
       logger.error("❌ Failed to add partial access site: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to add partial access site: " + e.getMessage()));
   }
}

/**
* Add multiple partial access sites (admin only)
*/
@PostMapping("/partial-access/bulk")
public ResponseEntity<ApiResponse<Map<String, Object>>> addBulkPartialAccessSites(
       @RequestBody PartialAccessRequest request) {
   try {
       if (request.getPartialAccessSites() == null || request.getPartialAccessSites().isEmpty()) {
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "No partial access sites provided"));
       }

       String addedBy = "admin"; // Get from authentication in production
       List<PartialAccessEntity> entities = partialAccessService.addPartialAccessSites(
           request.getPartialAccessSites(), addedBy);

       Map<String, Object> response = new HashMap<>();
       response.put("addedCount", entities.size());
       response.put("sites", entities.stream()
               .map(e -> Map.of(
                   "id", e.getId(),
                   "urlPattern", e.getUrlPattern(),
                   "domain", e.getDomain(),
                   "allowUpload", e.isAllowUpload(),
                   "allowDownload", e.isAllowDownload()
               ))
               .collect(Collectors.toList()));

       logger.info("✅ Added {} partial access sites in bulk", entities.size());
       return ResponseEntity.ok(new ApiResponse<>(true, "Partial access sites added in bulk", response));

   } catch (Exception e) {
       logger.error("❌ Failed to add bulk partial access sites: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to add partial access sites: " + e.getMessage()));
   }
}

/**
* Update partial access site (admin only)
*/
@PutMapping("/partial-access/{id}")
public ResponseEntity<ApiResponse<Map<String, Object>>> updatePartialAccessSite(
       @PathVariable Long id,
       @RequestBody PartialAccessRequest request) {
   try {
       PartialAccessEntity entity = partialAccessService.updatePartialAccessSite(id, request);

       Map<String, Object> response = new HashMap<>();
       response.put("id", entity.getId());
       response.put("urlPattern", entity.getUrlPattern());
       response.put("domain", entity.getDomain());
       response.put("allowUpload", entity.isAllowUpload());
       response.put("allowDownload", entity.isAllowDownload());
       response.put("monitorMode", entity.getMonitorMode());
       response.put("message", "Partial access site updated successfully");

       logger.info("✅ Partial access site updated: {} (Upload: {}, Download: {})",
           entity.getUrlPattern(), entity.isAllowUpload(), entity.isAllowDownload());
       return ResponseEntity.ok(new ApiResponse<>(true, "Partial access site updated", response));

   } catch (Exception e) {
       logger.error("❌ Failed to update partial access site: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to update partial access site: " + e.getMessage()));
   }
}

/**
* Delete partial access site (admin only)
*/
@DeleteMapping("/partial-access/{id}")
public ResponseEntity<ApiResponse<String>> deletePartialAccessSite(@PathVariable Long id) {
   try {
       partialAccessService.deletePartialAccessSite(id);
       return ResponseEntity.ok(new ApiResponse<>(true, "Partial access site deleted"));

   } catch (Exception e) {
       logger.error("❌ Failed to delete partial access site: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to delete partial access site: " + e.getMessage()));
   }
}

/**
* Delete partial access sites by patterns (admin only)
*/
@DeleteMapping("/partial-access")
public ResponseEntity<ApiResponse<Map<String, Object>>> deletePartialAccessSites(
       @RequestBody PartialAccessRequest request) {
   try {
       if (request.getDeletePatterns() == null || request.getDeletePatterns().isEmpty()) {
           return ResponseEntity.badRequest()
                   .body(new ApiResponse<>(false, "No patterns provided"));
       }

       int deletedCount = partialAccessService.deleteByPatterns(request.getDeletePatterns());

       Map<String, Object> response = new HashMap<>();
       response.put("deletedCount", deletedCount);
       response.put("message", deletedCount + " partial access site(s) deleted");

       return ResponseEntity.ok(new ApiResponse<>(true, "Partial access sites deleted", response));

   } catch (Exception e) {
       logger.error("❌ Failed to delete partial access sites: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to delete partial access sites: " + e.getMessage()));
   }
}

/**
* Toggle partial access site status (admin only)
*/
@PatchMapping("/partial-access/{id}/toggle")
public ResponseEntity<ApiResponse<Map<String, Object>>> togglePartialAccessSite(
       @PathVariable Long id,
       @RequestParam boolean active) {
   try {
       PartialAccessEntity entity = partialAccessService.togglePartialAccessSite(id, active);

       Map<String, Object> response = new HashMap<>();
       response.put("id", entity.getId());
       response.put("urlPattern", entity.getUrlPattern());
       response.put("active", entity.isActive());
       response.put("message", "Partial access site " + (active ? "activated" : "deactivated"));

       logger.info("🔄 Partial access site toggled: {} -> {}", entity.getUrlPattern(), active ? "active" : "inactive");
       return ResponseEntity.ok(new ApiResponse<>(true, "Partial access site status updated", response));

   } catch (Exception e) {
       logger.error("❌ Failed to toggle partial access site: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to toggle partial access site: " + e.getMessage()));
   }
}

/**
* Search partial access sites
*/
@GetMapping("/partial-access/search")
public ResponseEntity<ApiResponse<List<Map<String, Object>>>> searchPartialAccessSites(
       @RequestParam String keyword) {
   try {
       List<PartialAccessEntity> entities = partialAccessService.searchPartialAccessSites(keyword);

       List<Map<String, Object>> sites = entities.stream()
               .map(entity -> {
                   Map<String, Object> map = new HashMap<>();
                   map.put("id", entity.getId());
                   map.put("urlPattern", entity.getUrlPattern());
                   map.put("domain", entity.getDomain());
                   map.put("reason", entity.getReason());
                   map.put("category", entity.getCategory());
                   map.put("active", entity.isActive());
                   map.put("global", entity.isGlobal());
                   map.put("allowUpload", entity.isAllowUpload());
                   map.put("allowDownload", entity.isAllowDownload());
                   map.put("monitorMode", entity.getMonitorMode());
                   map.put("deviceId", entity.getDeviceId());
                   map.put("userId", entity.getUserId());
                   map.put("addedBy", entity.getAddedBy());
                   map.put("uploadAttempts", entity.getUploadAttempts());
                   map.put("downloadAttempts", entity.getDownloadAttempts());
                   map.put("createdAt", entity.getCreatedAt());
                   map.put("updatedAt", entity.getUpdatedAt());

                   // Parse restricted file types
                   try {
                       if (entity.getRestrictedFileTypes() != null && !entity.getRestrictedFileTypes().isEmpty()) {
                           List<String> fileTypes = objectMapper.readValue(
                               entity.getRestrictedFileTypes(),
                               new com.fasterxml.jackson.core.type.TypeReference<List<String>>() {}
                           );
                           map.put("restrictedFileTypes", fileTypes);
                       } else {
                           map.put("restrictedFileTypes", new ArrayList<>());
                       }
                   } catch (Exception e) {
                       map.put("restrictedFileTypes", new ArrayList<>());
                   }

                   return map;
               })
               .collect(Collectors.toList());

       return ResponseEntity.ok(new ApiResponse<>(true, "Search results", sites));

   } catch (Exception e) {
       logger.error("❌ Failed to search partial access sites: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to search partial access sites"));
   }
}

/**
* Get partial access site statistics
*/
@GetMapping("/partial-access/stats")
public ResponseEntity<ApiResponse<Map<String, Object>>> getPartialAccessStats() {
   try {
       Map<String, Object> stats = partialAccessService.getStatistics();
       return ResponseEntity.ok(new ApiResponse<>(true, "Partial access site statistics", stats));

   } catch (Exception e) {
       logger.error("❌ Failed to get partial access stats: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to get statistics"));
   }
}

/**
* Get most attempted partial access sites
*/
@GetMapping("/partial-access/most-attempted")
public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getMostAttemptedSites(
       @RequestParam(defaultValue = "10") int limit) {
   try {
       List<PartialAccessEntity> entities = partialAccessService.getMostAttemptedSites(limit);

       List<Map<String, Object>> sites = entities.stream()
               .map(entity -> {
                   Map<String, Object> map = new HashMap<>();
                   map.put("urlPattern", entity.getUrlPattern());
                   map.put("domain", entity.getDomain());
                   map.put("uploadAttempts", entity.getUploadAttempts());
                   map.put("downloadAttempts", entity.getDownloadAttempts());
                   map.put("totalAttempts", entity.getUploadAttempts() + entity.getDownloadAttempts());
                   map.put("allowUpload", entity.isAllowUpload());
                   map.put("allowDownload", entity.isAllowDownload());
                   return map;
               })
               .collect(Collectors.toList());

       return ResponseEntity.ok(new ApiResponse<>(true, "Most attempted partial access sites", sites));

   } catch (Exception e) {
       logger.error("❌ Failed to get most attempted sites: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to get most attempted sites"));
   }
}

/**
* Get partial access sites by category
*/
@GetMapping("/partial-access/category/{category}")
public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getPartialAccessByCategory(
       @PathVariable String category) {
   try {
       List<PartialAccessEntity> entities = partialAccessService.getPartialAccessByCategory(category);

       List<Map<String, Object>> sites = entities.stream()
               .map(entity -> {
                   Map<String, Object> map = new HashMap<>();
                   map.put("id", entity.getId());
                   map.put("urlPattern", entity.getUrlPattern());
                   map.put("domain", entity.getDomain());
                   map.put("reason", entity.getReason());
                   map.put("category", entity.getCategory());
                   map.put("active", entity.isActive());
                   map.put("global", entity.isGlobal());
                   map.put("allowUpload", entity.isAllowUpload());
                   map.put("allowDownload", entity.isAllowDownload());
                   map.put("monitorMode", entity.getMonitorMode());
                   map.put("deviceId", entity.getDeviceId());
                   map.put("userId", entity.getUserId());
                   map.put("addedBy", entity.getAddedBy());
                   map.put("uploadAttempts", entity.getUploadAttempts());
                   map.put("downloadAttempts", entity.getDownloadAttempts());
                   map.put("createdAt", entity.getCreatedAt());
                   map.put("updatedAt", entity.getUpdatedAt());
                   return map;
               })
               .collect(Collectors.toList());

       return ResponseEntity.ok(new ApiResponse<>(true, "Partial access sites by category", sites));

   } catch (Exception e) {
       logger.error("❌ Failed to get partial access sites by category: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to get partial access sites by category"));
   }
}

/**
* Record upload attempt (called from Python client)
*/
@PostMapping("/devices/{deviceId}/partial-access/upload-attempt")
public ResponseEntity<ApiResponse<String>> recordUploadAttempt(
       @PathVariable String deviceId,
       @RequestBody Map<String, Object> attemptData) {
   try {
       String url = (String) attemptData.get("url");
       String domain = (String) attemptData.get("domain");
       String fileType = (String) attemptData.get("fileType");
       boolean blocked = (boolean) attemptData.getOrDefault("blocked", false);
       String monitorMode = (String) attemptData.getOrDefault("monitorMode", "block");

       // Get device to get userId
       var deviceOpt = pythonClientService.getDeviceById(deviceId);
       if (deviceOpt.isPresent()) {
           var device = deviceOpt.get();
           partialAccessService.incrementUploadAttempt(url);
       }

       // Log to device logs
       String logMessage = String.format(
           "📤 Upload attempt on partial-access site - URL: %s, Domain: %s, File: %s, Blocked: %s, Mode: %s",
           url, domain, fileType, blocked, monitorMode
       );

       Map<String, Object> logData = new HashMap<>();
       logData.put("deviceId", deviceId);
       logData.put("logType", "partial_access");
       logData.put("logContent", logMessage);
       logData.put("fileSize", 0);

       pythonClientService.saveLog(logData);

       logger.info("📤 Upload attempt recorded - Device: {}, URL: {}, Blocked: {}",
           deviceId, domain, blocked);

       return ResponseEntity.ok(new ApiResponse<>(true, "Upload attempt recorded"));

   } catch (Exception e) {
       logger.error("❌ Failed to record upload attempt: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to record upload attempt"));
   }
}

/**
* Record download attempt (called from Python client)
*/
@PostMapping("/devices/{deviceId}/partial-access/download-attempt")
public ResponseEntity<ApiResponse<String>> recordDownloadAttempt(
       @PathVariable String deviceId,
       @RequestBody Map<String, Object> attemptData) {
   try {
       String url = (String) attemptData.get("url");
       String domain = (String) attemptData.get("domain");
       String fileType = (String) attemptData.get("fileType");
       boolean blocked = (boolean) attemptData.getOrDefault("blocked", false);
       String monitorMode = (String) attemptData.getOrDefault("monitorMode", "block");

       // Get device to get userId
       var deviceOpt = pythonClientService.getDeviceById(deviceId);
       if (deviceOpt.isPresent()) {
           var device = deviceOpt.get();
           partialAccessService.incrementDownloadAttempt(url);
       }

       // Log to device logs
       String logMessage = String.format(
           "📥 Download attempt on partial-access site - URL: %s, Domain: %s, File: %s, Blocked: %s, Mode: %s",
           url, domain, fileType, blocked, monitorMode
       );

       Map<String, Object> logData = new HashMap<>();
       logData.put("deviceId", deviceId);
       logData.put("logType", "partial_access");
       logData.put("logContent", logMessage);
       logData.put("fileSize", 0);

       pythonClientService.saveLog(logData);

       logger.info("📥 Download attempt recorded - Device: {}, URL: {}, Blocked: {}",
           deviceId, domain, blocked);

       return ResponseEntity.ok(new ApiResponse<>(true, "Download attempt recorded"));

   } catch (Exception e) {
       logger.error("❌ Failed to record download attempt: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to record download attempt"));
   }
}

/**
* Reset all attempts (admin only)
*/
@PostMapping("/partial-access/reset-attempts")
public ResponseEntity<ApiResponse<String>> resetAllAttempts() {
   try {
       partialAccessService.resetAllAttempts();
       return ResponseEntity.ok(new ApiResponse<>(true, "All upload/download attempts reset"));

   } catch (Exception e) {
       logger.error("❌ Failed to reset attempts: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to reset attempts"));
   }
}

/**
* Check if URL is in partial access list
*/
@GetMapping("/partial-access/check")
public ResponseEntity<ApiResponse<Map<String, Object>>> checkPartialAccess(
       @RequestParam String url,
       @RequestParam String deviceId,
       @RequestParam String userId) {
   try {
       boolean isPartialAccess = partialAccessService.isPartialAccessSite(url, deviceId, userId);
       boolean allowUpload = partialAccessService.isUploadAllowed(url, deviceId, userId);
       boolean allowDownload = partialAccessService.isDownloadAllowed(url, deviceId, userId);
       List<String> restrictedFileTypes = partialAccessService.getRestrictedFileTypes(url, deviceId, userId);
       String monitorMode = partialAccessService.getMonitorMode(url, deviceId, userId);

       Map<String, Object> result = new HashMap<>();
       result.put("isPartialAccess", isPartialAccess);
       result.put("allowUpload", allowUpload);
       result.put("allowDownload", allowDownload);
       result.put("restrictedFileTypes", restrictedFileTypes);
       result.put("monitorMode", monitorMode);
       result.put("url", url);
       result.put("deviceId", deviceId);
       result.put("userId", userId);

       return ResponseEntity.ok(new ApiResponse<>(true, "Partial access check complete", result));

   } catch (Exception e) {
       logger.error("❌ Failed to check partial access: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to check partial access"));
   }
}

/**
* Get daily app usage for a specific device
*/
@GetMapping("/devices/{deviceId}/app-usage/daily")
public ResponseEntity<ApiResponse<Map<String, Object>>> getDailyAppUsage(
       @PathVariable String deviceId,
       @RequestParam(required = false) String date) {
   try {
       LocalDate targetDate;
       if (date != null && !date.isEmpty()) {
           targetDate = LocalDate.parse(date);
       } else {
           targetDate = LocalDate.now();
       }

       Map<String, Object> dailyUsage = pythonClientService.getDailyAppUsage(deviceId, targetDate);

       logger.info("📱 Daily app usage retrieved for device {} on {}: {}s",
           deviceId, targetDate, dailyUsage.get("dailyUsage"));

       return ResponseEntity.ok(new ApiResponse<>(true, "Daily app usage retrieved", dailyUsage));

   } catch (Exception e) {
       logger.error("❌ Failed to get daily app usage: {}", e.getMessage());
       return ResponseEntity.badRequest()
               .body(new ApiResponse<>(false, "Failed to get daily app usage: " + e.getMessage()));
   }
}
}