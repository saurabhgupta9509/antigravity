package com.ma.dlp.dto;

import java.util.List;

public class UrlMonitoringRequest {
    private String deviceId;
    private String timestamp;
    private List<String> urls;
    private Integer blockedCount;
    private Integer suspiciousCount;
    private Integer totalVisits;


    public Integer getBlockedCount() {
        return blockedCount;
    }

    public void setBlockedCount(Integer blockedCount) {
        this.blockedCount = blockedCount;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public Integer getSuspiciousCount() {
        return suspiciousCount;
    }

    public void setSuspiciousCount(Integer suspiciousCount) {
        this.suspiciousCount = suspiciousCount;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public Integer getTotalVisits() {
        return totalVisits;
    }

    public void setTotalVisits(Integer totalVisits) {
        this.totalVisits = totalVisits;
    }

    public List<String> getUrls() {
        return urls;
    }

    public void setUrls(List<String> urls) {
        this.urls = urls;
    }
}