package com.ma.dlp.Repository;
import com.ma.dlp.model.PythonDevice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface PythonDeviceRepository extends JpaRepository<PythonDevice, Long> {
    Optional<PythonDevice> findByDeviceId(String deviceId);
    boolean existsByDeviceId(String deviceId);
    List<PythonDevice> findAllByOrderByLastHeartbeatDesc();

    @Query("SELECT d FROM PythonDevice d WHERE d.lastHeartbeat < :cutoff AND d.status = 'active'")
    List<PythonDevice> findInactiveDevices(@Param("cutoff") LocalDateTime cutoff);
}