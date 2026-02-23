// PythonCertificateRepository.java
package com.ma.dlp.Repository;

import com.ma.dlp.model.PythonCertificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface PythonCertificateRepository extends JpaRepository<PythonCertificate, Long> {
    Optional<PythonCertificate> findByCertificateId(String certificateId);
    List<PythonCertificate> findByDeviceIdOrderByUploadedAtDesc(String deviceId);
    List<PythonCertificate> findTop5ByDeviceIdOrderByUploadedAtDesc(String deviceId);
}