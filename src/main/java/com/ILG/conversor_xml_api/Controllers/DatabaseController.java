package com.ILG.conversor_xml_api.Controllers;

import com.ILG.conversor_xml_api.Models.DatabaseCredentials;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.web.bind.annotation.*;

import javax.sql.DataSource;

@RestController
@RequestMapping("/api/database")
public class DatabaseController {

    private DriverManagerDataSource dataSource;

    @PostMapping("/connect")
    public String connectToDatabase(@RequestBody DatabaseCredentials credentials) {
        this.dataSource = createDataSource(credentials);
        return "Conexão estabelecida com sucesso!";
    }

    private DriverManagerDataSource createDataSource(DatabaseCredentials credentials) {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();

        String jdbcUrl;
        String driverClassName;

        switch (credentials.getDbType().toLowerCase()) {
            case "mysql":
                String hostMysql = credentials.getDbHost() + ":" + credentials.getDbPort();
                jdbcUrl = String.format("jdbc:mysql://%s/%s",hostMysql, credentials.getDbName());
                driverClassName = "com.mysql.cj.jdbc.Driver";
                break;
            case "postgresql":
                String hostPostgres = credentials.getDbHost() + ":" + credentials.getDbPort();
                jdbcUrl = String.format("jdbc:postgresql://%s/%s",hostPostgres, credentials.getDbName());
                driverClassName = "org.postgresql.Driver";
                break;
            default:
                throw new IllegalArgumentException("Tipo de banco de dados não suportado: " + credentials.getDbType());
        }

        dataSource.setDriverClassName(driverClassName);
        dataSource.setUrl(jdbcUrl);
        dataSource.setUsername(credentials.getDbUser());
        dataSource.setPassword(credentials.getDbPassword());

        return dataSource;
    }

    // Método para obter o DataSource se necessário
    public DataSource getDataSource() {
        return dataSource;
    }

}
