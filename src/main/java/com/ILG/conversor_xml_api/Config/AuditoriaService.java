package com.ILG.conversor_xml_api.Config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class AuditoriaService {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // Método para registrar a auditoria
    public void logAudit(String actionType, String tableName, String recordId,
                         String oldValues, String newValues, String userId, String ipAddress) {
        String sql = "INSERT INTO audit_log (action_type, table_name, record_id, old_values, new_values, user_id, ip_address) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?)";

        // Usando o JdbcTemplate para executar a consulta
        jdbcTemplate.update(sql, actionType, tableName, recordId, oldValues, newValues, userId, ipAddress);
    }
}
