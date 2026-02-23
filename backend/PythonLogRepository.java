package com.ma.dlp.Repository;
import com.ma.dlp.model.PythonLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface PythonLogRepository extends JpaRepository<PythonLog, Long> {
    List<PythonLog> findByDeviceIdOrderByTimestampDesc(String deviceId);
    List<PythonLog> findByDeviceIdAndLogTypeOrderByTimestampDesc(String deviceId, String logType);
    void deleteByDeviceId(String deviceId);
}