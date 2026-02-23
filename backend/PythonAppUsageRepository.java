package com.ma.dlp.Repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.ma.dlp.model.PythonAppUsage;

@Repository
public interface PythonAppUsageRepository extends JpaRepository<PythonAppUsage, Long> {
    List<PythonAppUsage> findByDeviceIdOrderByTimestampDesc(String deviceId);
    List<PythonAppUsage> findTop10ByDeviceIdOrderByTimestampDesc(String deviceId);
    
    // Add this method for daily usage
    @Query("SELECT a FROM PythonAppUsage a WHERE a.deviceId = :deviceId AND a.timestamp >= :startDate AND a.timestamp < :endDate ORDER BY a.timestamp DESC")
    List<PythonAppUsage> findByDeviceIdAndTimestampBetween(
        @Param("deviceId") String deviceId,
        @Param("startDate") LocalDateTime startDate,
        @Param("endDate") LocalDateTime endDate);
}