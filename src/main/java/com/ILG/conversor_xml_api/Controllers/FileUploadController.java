package com.ILG.conversor_xml_api.Controllers;

import com.ILG.conversor_xml_api.Config.CustomMultipartFile;
import com.ILG.conversor_xml_api.Config.XmlProcessingResult;
import com.ILG.conversor_xml_api.Config.constants;
import com.ILG.conversor_xml_api.Models.DatabaseCredentials;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.apache.poi.ss.usermodel.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.SecretKey;
import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@RestController
@RequestMapping("/api/usuarios/arquivos")
//@CrossOrigin(origins = "http://localhost:5173", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.OPTIONS})
public class FileUploadController {

    @Autowired
    private DatabaseController databaseController;

    @GetMapping("/home")
    public ResponseEntity<String> api(){
        return ResponseEntity.ok("Conversor XML API 2.0");
    }

    @PostMapping("/configurarConexao")
    public ResponseEntity<Map<String, String>> configurarConexao(
            @RequestBody DatabaseCredentials connection) {

        boolean isConnected = false;
        DataSource dataSource = null;

        try {
            databaseController.connectToDatabase(new DatabaseCredentials(
                    connection.getDbType(),
                    connection.getDbHost(),
                    connection.getDbPort(),
                    connection.getDbUser(),
                    connection.getDbPassword(),
                    connection.getDbName()
            ));
            dataSource = databaseController.getDataSource();
            JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);

            // Testa a conexão:
            jdbcTemplate.execute("SELECT 1");
            isConnected = true;
        } catch (Exception e) {
            isConnected = false;
        } finally {
            if (dataSource != null) {
                try {
                    dataSource.getConnection().close();
                } catch (SQLException sqle) {
                    sqle.printStackTrace();
                }
            }
        }

        System.out.println(connection.getDbHost());
        System.out.println(connection.getDbType());
        System.out.println(connection.getDbName());
        System.out.println(connection.getDbPort());
        System.out.println(connection.getDbPassword());
        System.out.println(connection.getDbUser());


        if (!isConnected) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("message", "Falha na conexão com o banco de dados. Verifique as credenciais.");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }

        // Conexão bem-sucedida, gerar token de conexão
        String tokenConexao = generateConnectionToken(
                connection.getDbType(),
                connection.getDbHost(),
                connection.getDbPort(),
                connection.getDbUser(),
                connection.getDbPassword(),
                connection.getDbName()
        );

        Map<String, String> responseMap = new HashMap<>();
        responseMap.put("token_conexao", tokenConexao);
        responseMap.put("message", "Conexão realizada com sucesso!");
        return ResponseEntity.ok(responseMap);
    }




    // Método para gerar o token de conexão
    private String generateConnectionToken(String dbType, String dbHost, int dbPort, String dbUser, String dbPassword, String dbName) {
        long timestamp = System.currentTimeMillis();

        SecretKey secretKey = Keys.hmacShaKeyFor(constants.API_SECRET_KEY.getBytes());
        return Jwts.builder()
                .setIssuedAt(new java.sql.Date(timestamp))
                .setExpiration(new java.sql.Date(timestamp + constants.TOKEN_VALIDITY))
                .claim("dbType", dbType)
                .claim("dbHost", dbHost)
                .claim("dbPort", dbPort)
                .claim("dbUser", dbUser)
                .claim("dbPassword", dbPassword)
                .claim("dbName", dbName)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }


    @PostMapping("/upload")
    public ResponseEntity<Map<String, String>> uploadFile(@RequestParam("file") MultipartFile file,
                                                          @RequestParam("fileName") String fileNameInput,
                                                          @RequestHeader("ConnectionToken") String connectionToken,
                                                          @RequestParam("tableName") String tableName) {
        DataSource dataSource = null;

        final long MAX_FILE_SIZE = 2 * 1024 * 1024;

        Long auditoriaId = null;

        try {

            System.out.println(file.getSize());

            if (file.getSize() > MAX_FILE_SIZE) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                        "codeHttp", HttpStatus.INTERNAL_SERVER_ERROR.toString(),
                        "message", "Erro! Arquivo com Tamanho Acima do Permitido!",
                        "Status", "Error"
                ));
            }

            // Configuração da chave secreta para decodificar o token
            SecretKey secretKey = Keys.hmacShaKeyFor(constants.API_SECRET_KEY.getBytes());
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(connectionToken)
                    .getBody();

            String dbType = claims.get("dbType", String.class);
            String dbHost = claims.get("dbHost", String.class);
            int dbPort = claims.get("dbPort", Integer.class);
            String dbUser = claims.get("dbUser", String.class);
            String dbPassword = claims.get("dbPassword", String.class);
            String dbName = claims.get("dbName", String.class);

            // Estabelece conexão com o banco de dados usando as credenciais
            databaseController.connectToDatabase(new DatabaseCredentials(dbType, dbHost, dbPort, dbUser, dbPassword, dbName));
            dataSource = databaseController.getDataSource();
            JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);

            // Determina o tipo de arquivo a partir da extensão
            String fileExtension = getFileExtension(file.getOriginalFilename());

            // Condicional para arquivos XML ou XLSX diretamente
            if (fileExtension.equalsIgnoreCase("xml")) {
                // Converter MultipartFile para File
                File xmlFile = convertMultipartFileToFile(file);
                // Processar arquivo XML
                XmlProcessingResult processingResult = processXmlFile(xmlFile); // Agora passa um File
                Element rootElement = (Element) processingResult.getRootElement(); // Elemento raiz
                Map<String, String> columns = processingResult.getColumns(); // Colunas extraídas

                if(!createTable(jdbcTemplate, dbType, tableName, columns)){
                    Map<String, String> responseMap = new LinkedHashMap<>();
                    responseMap.put("status", HttpStatus.BAD_REQUEST.toString());
                    responseMap.put("message", "Tabela já existente!");
                    return new ResponseEntity<>(responseMap, HttpStatus.BAD_REQUEST);
                }

                String fileNamePar = (fileNameInput.length() > 0) ? fileNameInput : xmlFile.getName();
                auditoriaId = insertDataIntoTable(jdbcTemplate, tableName, rootElement, fileNamePar, dbType);

            } else if (fileExtension.equalsIgnoreCase("xlsx")) {
                // Processar arquivo XLSX
                Map<String, String> columns = processXlsxFile(file);
                if(!createTable(jdbcTemplate, dbType, tableName, columns)){
                    Map<String, String> responseMap = new HashMap<>();
                    responseMap.put("status", HttpStatus.BAD_REQUEST.toString());
                    responseMap.put("message", "Tabela já existente!");
                    return new ResponseEntity<>(responseMap, HttpStatus.BAD_REQUEST);
                }
                String fileNamePar = (fileNameInput.length() > 0) ? fileNameInput : file.getOriginalFilename();
                auditoriaId = insertDataIntoTableXLS(jdbcTemplate, tableName, file, fileNamePar, dbType);

            } else if (fileExtension.equalsIgnoreCase("zip")) {
                // Descompactar o arquivo ZIP ou RAR se necessário
                File extractedFile = extractFileIfNeeded(file);

                long totalSize = 0;

                for (File subFile : extractedFile.listFiles()) {
                    totalSize += subFile.length();
                }

                System.out.println(totalSize);

                if (totalSize > MAX_FILE_SIZE) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                            "codeHttp", HttpStatus.INTERNAL_SERVER_ERROR.toString(),
                            "message", "Erro! Arquivo com Tamanho Acima do Permitido: ",
                            "Status", "Error"
                    ));
                }

                // Processar arquivos contidos no diretório extraído
                for (File subFile : extractedFile.listFiles()) {
                    String subFileExtension = getFileExtension(subFile.getName());
                    CustomMultipartFile multipartFile = new CustomMultipartFile(subFile); // Use CustomMultipartFile

                    if (subFileExtension.equalsIgnoreCase("xml")) {
                        // Processar arquivo XML
                        XmlProcessingResult processingResult = processXmlFile(subFile); // Obtenha o resultado
                        Element rootElement = (Element) processingResult.getRootElement(); // Elemento raiz
                        Map<String, String> columns = processingResult.getColumns(); // Colunas extraídas

                        if(!createTable(jdbcTemplate, dbType, tableName, columns)){
                            Map<String, String> responseMap = new HashMap<>();
                            responseMap.put("status", HttpStatus.BAD_REQUEST.toString());
                            responseMap.put("message", "Tabela já existente!");
                            return new ResponseEntity<>(responseMap, HttpStatus.BAD_REQUEST);
                        }
                        String fileNamePar = (fileNameInput.length() > 0) ? fileNameInput : subFile.getName();
                        auditoriaId = insertDataIntoTable(jdbcTemplate, tableName, rootElement, fileNamePar, dbType);

                    } else if (subFileExtension.equalsIgnoreCase("xlsx")) {
                        // Processar arquivo XLSX
                        Map<String, String> columns = processXlsxFile(multipartFile); // Use CustomMultipartFile
                        if(!createTable(jdbcTemplate, dbType, tableName, columns)){
                            Map<String, String> responseMap = new HashMap<>();
                            responseMap.put("status", HttpStatus.BAD_REQUEST.toString());
                            responseMap.put("message", "Tabela já existente!");
                            return new ResponseEntity<>(responseMap, HttpStatus.BAD_REQUEST);
                        }
                        String fileNamePar = (fileNameInput.length() > 0) ? fileNameInput : subFile.getName();
                        auditoriaId = insertDataIntoTableXLS(jdbcTemplate, tableName, multipartFile, fileNamePar, dbType);
                    } else {
                        return ResponseEntity.badRequest().body(Map.of("message", "Tipo de arquivo não suportado: " + subFileExtension));
                    }
                }
            } else {
                return ResponseEntity.badRequest().body(Map.of("message", "Tipo de arquivo não suportado."));
            }

            return ResponseEntity.ok(Map.of(
                    "codeHttp", HttpStatus.OK.toString(),
                    "message", "Arquivo processado e dados inseridos com sucesso!",
                    "Status", "Success",
                    "id", String.valueOf(auditoriaId),
                    "tableName", tableName
            ));

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "codeHttp", HttpStatus.INTERNAL_SERVER_ERROR.toString(),
                    "message", "Erro ao processar arquivo: " + e.getMessage(),
                    "Status", "Error"
            ));
        } finally {
            if (dataSource != null) {
                try {
                    dataSource.getConnection().close();
                } catch (SQLException sqle) {
                    sqle.printStackTrace();
                }
            }
        }
    }
    private File convertMultipartFileToFile(MultipartFile file) throws IOException {
        // Salve em um diretório temporário
        Path tempDir = Paths.get(System.getProperty("java.io.tmpdir"));
        File convertedFile = tempDir.resolve(file.getOriginalFilename()).toFile();
        file.transferTo(convertedFile);
        return convertedFile;
    }



    private File extractFileIfNeeded(MultipartFile file) throws IOException {
        // Verifica se o arquivo é um ZIP ou XML
        if (getFileExtension(file.getOriginalFilename()).equalsIgnoreCase("zip")) {
            // Código para descompactar arquivos ZIP, como já está implementado
            return extractZipFile(file);
        } else if (getFileExtension(file.getOriginalFilename()).equalsIgnoreCase("xml")) {
            // Se for XML, apenas salva o arquivo
            File tempFile = new File(Files.createTempDirectory("extracted").toFile(), file.getOriginalFilename());
            file.transferTo(tempFile);
            return tempFile;
        } else {
            throw new IOException("Arquivo não suportado. Somente ZIP e XML são permitidos.");
        }
    }

    private File extractZipFile(MultipartFile file) throws IOException {
        File tempDir = Files.createTempDirectory("extracted").toFile();
        try (InputStream inputStream = file.getInputStream()) {
            try (ZipInputStream zipIn = new ZipInputStream(inputStream)) {
                ZipEntry entry;
                while ((entry = zipIn.getNextEntry()) != null) {
                    File newFile = new File(tempDir, entry.getName());
                    if (entry.isDirectory()) {
                        newFile.mkdirs();
                    } else {
                        new File(newFile.getParent()).mkdirs();
                        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(newFile))) {
                            byte[] buffer = new byte[4096];
                            int len;
                            while ((len = zipIn.read(buffer)) > 0) {
                                bos.write(buffer, 0, len);
                            }
                        }
                    }
                }
            }
        }
        return tempDir;
    }

    // Método para obter a extensão do arquivo
    private String getFileExtension(String fileName) {
        if (fileName != null && fileName.lastIndexOf('.') > 0) {
            return fileName.substring(fileName.lastIndexOf('.') + 1);
        }
        return "";
    }



    private Map<String, String> processXlsxFile(MultipartFile file) throws IOException {
        Map<String, String> columns = new HashMap<>();
        System.out.println("Processando arquivo XLSX: " + file.getOriginalFilename());

        try (Workbook workbook = WorkbookFactory.create(file.getInputStream())) {
            Sheet sheet = workbook.getSheetAt(0); // Pega a primeira planilha
            Row headerRow = sheet.getRow(0); // Pega a linha de cabeçalho

            if (headerRow == null) {
                throw new IllegalArgumentException("A linha de cabeçalho está vazia.");
            }

            for (int i = 0; i < headerRow.getPhysicalNumberOfCells(); i++) {
                Cell cell = headerRow.getCell(i);
                if (cell != null) {
                    String originalColumnName = cell.getStringCellValue().trim();
                    String sanitizedColumnName = sanitizeColumnName(originalColumnName);
                    columns.put(sanitizedColumnName, "VARCHAR(255)"); // Defina o tipo de dados conforme necessário
                }
            }
        }

        return columns;
    }



    // Função para processar arquivo XML e extrair colunas
    private XmlProcessingResult processXmlFile(File xmlFile) throws Exception {
        Map<String, String> columns = new LinkedHashMap<>();

        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(xmlFile);
        doc.getDocumentElement().normalize();

        // Obtenha diretamente o elemento raiz
        Element rootElement = doc.getDocumentElement();

        NodeList childNodes = rootElement.getChildNodes();

        for (int i = 0; i < childNodes.getLength(); i++) {
            Node node = childNodes.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) node;
                String columnName = element.getTagName();
                String columnType = determineColumnType(element.getTextContent());
                columns.put(columnName, columnType);
            }
        }

        return new XmlProcessingResult(rootElement, columns); // Retorne os resultados
    }

    private String determineColumnType(String value) {
        try {
            Integer.parseInt(value);
            return "INT";
        } catch (NumberFormatException e) {
            try {
                Double.parseDouble(value);
                return "DOUBLE PRECISION";
            } catch (NumberFormatException ex) {
                //return "VARCHAR(255)";
                return "TEXT";
            }
        }
    }

    private boolean createTable(JdbcTemplate jdbcTemplate, String dbType, String tableName, Map<String, String> columns) {

        String checkTableExistsQuery = "";

        if (dbType.equalsIgnoreCase("postgresql")) {
            checkTableExistsQuery = "SELECT COUNT(*) FROM information_schema.tables WHERE lower(table_name) = lower(?) AND table_schema = 'public'";
            System.out.println("Já existe no POSTGRES!");

        } else if (dbType.equalsIgnoreCase("mysql")) {
            checkTableExistsQuery = "SELECT COUNT(*) FROM information_schema.tables WHERE lower(table_name) = lower(?) AND table_schema = DATABASE()";
            System.out.println("Já existe no Mysql!");
        }

        int tableExists = jdbcTemplate.queryForObject(checkTableExistsQuery, new Object[]{tableName}, Integer.class);

        if (tableExists > 0) {
            System.out.println("Tabela '" + tableName + "' já existe.");
            return false;
        } else {
            // Criação da tabela
            String createTableQuery = "";
            if (dbType.equalsIgnoreCase("postgresql")) {
                createTableQuery = "CREATE TABLE IF NOT EXISTS " + tableName
                        + " (id SERIAL PRIMARY KEY, dataArquivo TIMESTAMP WITH TIME ZONE, nomeArquivo VARCHAR(255))";
            } else if (dbType.equalsIgnoreCase("mysql")) {
                createTableQuery = "CREATE TABLE IF NOT EXISTS " + tableName
                        + " (id INT AUTO_INCREMENT PRIMARY KEY, dataArquivo TIMESTAMP, nomeArquivo VARCHAR(255))";
            }

            jdbcTemplate.execute(createTableQuery);
            System.out.println("Tabela '" + tableName + "' foi criada com sucesso.");
        }

        // Verifica colunas existentes
        String sqlExistingColumns = "";
        if (dbType.equalsIgnoreCase("postgresql")) {
            sqlExistingColumns = "SELECT column_name FROM information_schema.columns WHERE lower(table_name) = lower(?) AND table_schema = 'public'";
        } else if (dbType.equalsIgnoreCase("mysql")) {
            sqlExistingColumns = "SELECT column_name FROM information_schema.columns WHERE lower(table_name) = lower(?)";
        }

        Set<String> existingColumns = new HashSet<>(jdbcTemplate.queryForList(
                sqlExistingColumns,
                String.class, tableName));

        // Adicionar novas colunas
        for (Map.Entry<String, String> column : columns.entrySet()) {
            if (!existingColumns.contains(column.getKey())) {
                String addColumnQuery = "ALTER TABLE " + tableName + " ADD COLUMN " + column.getKey() + " " + column.getValue();
                jdbcTemplate.execute(addColumnQuery);
                System.out.println("Coluna '" + column.getKey() + "' adicionada na tabela '" + tableName + "'.");
            }
        }
        return true;
    }


    public Long insertDataIntoTableXLS(JdbcTemplate jdbcTemplate, String tableName, MultipartFile file, String fileName, String dbType) throws IOException {
        Long auditoriaId;
        try (Workbook workbook = WorkbookFactory.create(file.getInputStream())) {
            Sheet sheet = workbook.getSheetAt(0);

            Row headerRow = sheet.getRow(0);
            if (headerRow == null) {
                throw new IllegalArgumentException("O arquivo XLSX não contém cabeçalhos na primeira linha.");
            }

            Map<Integer, String> columnMap = new HashMap<>();
            for (int cellIndex = 0; cellIndex < headerRow.getPhysicalNumberOfCells(); cellIndex++) {
                Cell headerCell = headerRow.getCell(cellIndex);
                if (headerCell != null) {
                    String columnName = sanitizeColumnName(headerCell.getStringCellValue().trim());
                    columnMap.put(cellIndex, columnName);
                }
            }

            checkAndCreateAuditTable(jdbcTemplate);

            checkAndAddAuditIdColumn(jdbcTemplate, tableName, dbType); // Verifica e adiciona auditoria_id, se necessário
            auditoriaId = logAudit(jdbcTemplate, "INSERÇÃO", tableName, null, null, columnMap.toString());

            for (int rowIndex = 1; rowIndex <= sheet.getPhysicalNumberOfRows(); rowIndex++) {
                Row row = sheet.getRow(rowIndex);
                if (row == null) continue;

                StringBuilder columns = new StringBuilder("auditoria_id, dataArquivo, nomeArquivo");
                StringBuilder values = new StringBuilder("?, ?, ?");
                List<Object> valueList = new ArrayList<>(List.of(auditoriaId, new Timestamp(new Date().getTime()), fileName));

                for (int cellIndex = 0; cellIndex < row.getPhysicalNumberOfCells(); cellIndex++) {
                    Cell cell = row.getCell(cellIndex);
                    if (cell != null) {
                        String columnName = columnMap.get(cellIndex);
                        columns.append(", ").append(columnName);
                        values.append(", ?");
                        valueList.add(getCellValue(cell));
                    }
                }

                String sql = "INSERT INTO " + tableName + " (" + columns.toString() + ") VALUES (" + values.toString() + ")";
                jdbcTemplate.update(sql, valueList.toArray());
            }
        }

        return auditoriaId;
    }


    // Função para formatar os nomes das colunas
    private String sanitizeColumnName(String columnName) {
        if (columnName == null || columnName.trim().isEmpty()) {
            throw new IllegalArgumentException("O nome da coluna não pode ser nulo ou vazio");
        }
        // Substituir espaços por underscore e remover caracteres especiais
        return columnName.trim().replaceAll("[^a-zA-Z0-9_]", "_").toLowerCase();
    }

    private Object getCellValue(Cell cell) {
        FormulaEvaluator evaluator = cell.getSheet().getWorkbook().getCreationHelper().createFormulaEvaluator();

        switch (cell.getCellType()) {
            case NUMERIC:
                // Verifica se o número é uma data
                if (DateUtil.isCellDateFormatted(cell)) {
                    return cell.getDateCellValue(); // Retorna a data
                } else {
                    return cell.getNumericCellValue(); // Retorna o valor numérico
                 }
            case STRING:
                return cell.getStringCellValue(); // Retorna o valor de texto
            case BOOLEAN:
                return cell.getBooleanCellValue(); // Retorna valor booleano
            case FORMULA:
                // Avalia e retorna o valor calculado da fórmula
                CellValue cellValue = evaluator.evaluate(cell);
                switch (cellValue.getCellType()) {
                    case NUMERIC:
                        if (DateUtil.isCellDateFormatted(cell)) {
                            return cell.getDateCellValue(); // Caso seja uma data
                        } else {
                            return cellValue.getNumberValue(); // Valor numérico
                        }
                    case STRING:
                        return cellValue.getStringValue(); // Valor de texto
                    case BOOLEAN:
                        return cellValue.getBooleanValue(); // Valor booleano
                    default:
                        return null; // Para outros casos
                }
            case BLANK:
                return null; // Valor nulo para células em branco
            default:
                return null;
        }
    }


    public Long insertDataIntoTable(JdbcTemplate jdbcTemplate, String tableName, Element rootElement, String fileName, String dbType) {
        StringBuilder columns = new StringBuilder();
        StringBuilder values = new StringBuilder();
        List<Object> valueList = new ArrayList<>();
        Map<String, String> columnValueMap = new HashMap<>();

        checkAndCreateAuditTable(jdbcTemplate);

        // Verificar e adicionar o campo auditoria_id, se necessário
        checkAndAddAuditIdColumn(jdbcTemplate, tableName, dbType);

        // Inserir registro na tabela de auditoria e obter o ID gerado
        Long auditoriaId = logAudit(jdbcTemplate, "INSERÇÃO", tableName, null, null, columnValueMap.toString());

        // Processar elementos XML para preencher columnValueMap
        processElementRecursively(jdbcTemplate, tableName, rootElement, columns, values, valueList, "", columnValueMap);

        // Adicionar colunas e valores na ordem correta
        columns.append("auditoria_id, dataArquivo, nomeArquivo");
        values.append("?, ?, ?");

        // Adicionar os valores correspondentes
        valueList.add(auditoriaId);
        valueList.add(new Timestamp(new Date().getTime()));
        valueList.add(fileName);

        // Adicionar colunas do XML no columnValueMap na ordem correta
        for (Map.Entry<String, String> entry : columnValueMap.entrySet()) {
            columns.append(", ").append(entry.getKey());
            values.append(", ?");
            valueList.add(entry.getValue());
        }

        // Montar e executar o SQL de inserção
        String sql = "INSERT INTO " + tableName + " (" + columns.toString() + ") VALUES (" + values.toString() + ")";
        jdbcTemplate.update(sql, valueList.toArray());
        return auditoriaId;
    }


    public void checkAndAddAuditIdColumn(JdbcTemplate jdbcTemplate, String tableName, String dbType) {
        try {
            // Verifica se a coluna auditoria_id já existe
            String sqlCheck;

            if (dbType.equalsIgnoreCase("postgresql")) {
                sqlCheck = "SELECT column_name " +
                        "FROM information_schema.columns " +
                        "WHERE table_name = lower(?) AND column_name = 'auditoria_id'";
            } else if (dbType.equalsIgnoreCase("mysql")) {
                sqlCheck = "SELECT column_name " +
                        "FROM information_schema.columns " +
                        "WHERE table_schema = DATABASE() AND table_name = ? AND column_name = 'auditoria_id'";
            } else {
                throw new UnsupportedOperationException("Tipo de banco de dados não suportado: " + dbType);
            }

            List<String> columns = jdbcTemplate.query(sqlCheck, new Object[]{tableName},
                    (rs, rowNum) -> rs.getString("column_name"));

            // Se a coluna não existe, adiciona
            if (columns.isEmpty()) {
                String sqlAddColumn = "ALTER TABLE " + tableName + " ADD COLUMN auditoria_id BIGINT";
                jdbcTemplate.execute(sqlAddColumn);
                System.out.println("Coluna 'auditoria_id' adicionada com sucesso na tabela " + tableName);
            } else {
                System.out.println("A coluna 'auditoria_id' já existe na tabela " + tableName);
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Erro ao verificar/adicionar a coluna 'auditoria_id' na tabela " + tableName + ": " + e.getMessage());
        }
    }

    private void checkAndCreateAuditTable(JdbcTemplate jdbcTemplate) {
        String checkTableSql = """
        SELECT COUNT(*) 
        FROM information_schema.tables 
        WHERE table_name = 'audit_log'
    """;

        // Verifica se a tabela já existe
        Boolean tableExists = jdbcTemplate.queryForObject(checkTableSql, Boolean.class);

        // Cria a tabela apenas se ela não existir
        if (!Boolean.TRUE.equals(tableExists)) {
            String createTableSql = """
            CREATE TABLE audit_log (
                id BIGSERIAL PRIMARY KEY,
                action_type VARCHAR(50),
                table_name VARCHAR(100),
                record_id VARCHAR(255),
                old_values TEXT,
                new_values TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """;
            jdbcTemplate.execute(createTableSql);
        }
    }

    private Long logAudit(JdbcTemplate jdbcTemplate, String actionType, String tableName, String recordId,
                          String oldValues, String newValues) {
        String sql = "INSERT INTO audit_log (action_type, table_name, record_id, old_values, new_values) "
                + "VALUES (?, ?, ?, ?, ?)";

        // Usando KeyHolder para capturar o ID gerado
        KeyHolder keyHolder = new GeneratedKeyHolder();
        jdbcTemplate.update(connection -> {
            PreparedStatement ps = connection.prepareStatement(sql, new String[]{"id"});
            ps.setString(1, actionType);
            ps.setString(2, tableName);
            ps.setString(3, recordId);
            ps.setString(4, oldValues);
            ps.setString(5, newValues);
            return ps;
        }, keyHolder);

        // Retorna o ID gerado
        return keyHolder.getKey() != null ? keyHolder.getKey().longValue() : null;
    }

    public void updateDataInTable(JdbcTemplate jdbcTemplate, String tableName, Element rootElement, String fileName, Long auditoriaId) {
        StringBuilder setClause = new StringBuilder();
        List<Object> valueList = new ArrayList<>();
        Map<String, String> columnValueMap = new HashMap<>();

        // 1. Capturar os valores atuais do registro usando auditoria_id
        String currentValuesSql = "SELECT * FROM " + tableName + " WHERE auditoria_id = ?";
        Map<String, Object> currentValues = jdbcTemplate.queryForMap(currentValuesSql, auditoriaId);

        // Processar elementos XML para preencher o columnValueMap
        processElementRecursively(jdbcTemplate, tableName, rootElement, new StringBuilder(), new StringBuilder(), valueList, "", columnValueMap);

        // Adicionar colunas e valores atualizados no setClause
        setClause.append("dataArquivo = ?, nomeArquivo = ?");
        valueList.add(new Timestamp(new Date().getTime()));
        valueList.add(fileName);

        for (Map.Entry<String, String> entry : columnValueMap.entrySet()) {
            setClause.append(", ").append(entry.getKey()).append(" = ?");
            valueList.add(entry.getValue());
        }

        // 2. Construir e executar o comando SQL de atualização usando auditoria_id
        String sql = "UPDATE " + tableName + " SET " + setClause.toString() + " WHERE auditoria_id = ?";
        valueList.add(auditoriaId);
        jdbcTemplate.update(sql, valueList.toArray());

        // 3. Registrar a alteração na tabela de auditoria
        String previousValues = currentValues.toString(); // Valores antes do update
        String newValues = columnValueMap.toString(); // Novos valores após o update
        logAudit(jdbcTemplate, "ATUALIZAÇÃO", tableName, String.valueOf(auditoriaId), previousValues, newValues);
    }



    public void updateDataInTableXLS(JdbcTemplate jdbcTemplate, String tableName, MultipartFile file, String fileName, Long auditoriaId) throws IOException {
        try (Workbook workbook = WorkbookFactory.create(file.getInputStream())) {
            Sheet sheet = workbook.getSheetAt(0);

            Row headerRow = sheet.getRow(0);
            if (headerRow == null) {
                throw new IllegalArgumentException("O arquivo XLSX não contém cabeçalhos na primeira linha.");
            }

            // Mapeia os índices das colunas para os nomes das colunas no banco de dados
            Map<Integer, String> columnMap = new HashMap<>();
            for (int cellIndex = 0; cellIndex < headerRow.getPhysicalNumberOfCells(); cellIndex++) {
                Cell headerCell = headerRow.getCell(cellIndex);
                if (headerCell != null) {
                    String columnName = sanitizeColumnName(headerCell.getStringCellValue().trim());
                    columnMap.put(cellIndex, "\"" + columnName + "\"");
                }
            }

            Timestamp currentTimestamp = new Timestamp(new Date().getTime());

            // Obter os IDs dos registros que serão atualizados
            String idQuery = "SELECT id FROM " + tableName + " WHERE auditoria_id = ? ORDER BY id ASC";
            List<Long> recordIds = jdbcTemplate.queryForList(idQuery, new Object[]{auditoriaId}, Long.class);

            if (recordIds.size() < sheet.getPhysicalNumberOfRows() - 1) { // Verifica se há menos registros no banco do que linhas na planilha
                throw new IllegalArgumentException("O número de registros no banco de dados é menor do que o número de linhas na planilha.");
            }

            // Itera sobre cada linha da planilha, a partir da segunda linha (linha 1 em zero-index)
            for (int rowIndex = 1; rowIndex <= sheet.getPhysicalNumberOfRows() - 1; rowIndex++) {
                Row row = sheet.getRow(rowIndex);
                if (row == null) continue;

                Long currentId = recordIds.get(rowIndex - 1); // Obtém o ID correspondente ao índice atual

                // Capturar os valores atuais do registro antes da atualização
                String currentValuesSql = "SELECT * FROM " + tableName + " WHERE id = ?";
                Map<String, Object> currentValues = jdbcTemplate.queryForMap(currentValuesSql, currentId);

                List<Object> valueList = new ArrayList<>();
                StringBuilder setClause = new StringBuilder();

                // Processa cada célula da linha
                for (int cellIndex = 0; cellIndex < row.getPhysicalNumberOfCells(); cellIndex++) {
                    Cell cell = row.getCell(cellIndex);
                    if (cell != null) {
                        String columnName = columnMap.get(cellIndex);
                        if (columnName != null) {
                            if (setClause.length() > 0) {
                                setClause.append(", ");
                            }
                            setClause.append(columnName).append(" = ?");
                            valueList.add(getCellValue(cell));
                        }
                    }
                }

                // Adiciona as colunas "dataArquivo" e "nomeArquivo" ao SET clause para atualização
                setClause.append(", \"dataarquivo\" = ?, \"nomearquivo\" = ?");
                valueList.add(currentTimestamp);  // Valor para dataArquivo
                valueList.add(fileName);         // Valor para nomeArquivo

                // Prepara a query UPDATE
                String sql = "UPDATE " + tableName + " SET " + setClause + " WHERE id = ?";
                valueList.add(currentId);  // Adiciona o ID do registro ao WHERE

                // Executa o update
                jdbcTemplate.update(sql, valueList.toArray());

                // Capturar os valores novos (alterados) para auditoria
                Map<String, Object> newValues = new HashMap<>();
                for (int cellIndex = 0; cellIndex < row.getPhysicalNumberOfCells(); cellIndex++) {
                    Cell cell = row.getCell(cellIndex);
                    if (cell != null) {
                        String columnName = columnMap.get(cellIndex);
                        if (columnName != null) {
                            newValues.put(columnName, getCellValue(cell));
                        }
                    }
                }
                newValues.put("dataarquivo", currentTimestamp);
                newValues.put("nomearquivo", fileName);

                // Registrar auditoria
                logAudit(jdbcTemplate, "ATUALIZAÇÃO", tableName, String.valueOf(currentId), currentValues.toString(), newValues.toString());
            }
        }
    }






    // Função recursiva para processar elementos aninhados e garantir que as colunas existam no banco de dados
    private boolean processElementRecursively(JdbcTemplate jdbcTemplate, String tableName, Element element,
                                              StringBuilder columns, StringBuilder values, List<Object> valueList,
                                              String parentPrefix, Map<String, String> columnValueMap) {
        NodeList elementChildNodes = element.getChildNodes();
        String currentPrefix = parentPrefix.isEmpty() ? element.getTagName() : parentPrefix + "_" + element.getTagName();
        boolean hasData = false;

        for (int j = 0; j < elementChildNodes.getLength(); j++) {
            Node childNode = elementChildNodes.item(j);
            if (childNode.getNodeType() == Node.ELEMENT_NODE) {
                Element childElement = (Element) childNode;
                String columnName = currentPrefix + "_" + childElement.getTagName();
                String columnValue = childElement.getTextContent().trim();

                if (childElement.getChildNodes().getLength() > 1) {
                    // Processa recursivamente as tags filhas
                    boolean childHasData = processElementRecursively(jdbcTemplate, tableName, childElement, columns, values, valueList, currentPrefix, columnValueMap);
                    if (childHasData) {
                        hasData = true;
                    }
                } else {
                    if (columnValue.isEmpty() && childElement.getChildNodes().getLength() > 1) {
                        // Se o valor da tag pai estiver vazio e ela tiver tags filhas, preenchê-la com "VARCHAR TAG_PAI"
                        columnValue = "TAG_PAI";
                        System.out.println("TAG_PAI");

                    }
                    System.out.println(columnValue);


                    if (!columnValue.isEmpty()) {
                        createColumnIfNotExists(jdbcTemplate, tableName, columnName, "TEXT");

                        // Verificar se a coluna já existe no mapa e concatenar o valor
                        if (columnValueMap.containsKey(columnName)) {
                            // Concatenar os valores com um delimitador
                            String existingValue = columnValueMap.get(columnName);
                            columnValueMap.put(columnName, existingValue + "; " + columnValue);
                        } else {
                            // Adicionar ao mapa se ainda não existir
                            columnValueMap.put(columnName, columnValue);
                        }

                        hasData = true;
                    }
                }
            }
        }

        return hasData;
    }



    // Função para verificar se uma coluna existe, e se não, criar uma nova coluna:

    private void createColumnIfNotExists(JdbcTemplate jdbcTemplate, String tableName, String columnName, String columnType) {
        String checkColumnQuery = "SELECT column_name FROM information_schema.columns WHERE lower(table_name) = lower(?) AND lower(column_name) = lower(?)";
        List<String> existingColumns = jdbcTemplate.queryForList(checkColumnQuery, String.class, tableName, columnName.toLowerCase());

        if (existingColumns.isEmpty()) {
            String addColumnQuery = "ALTER TABLE " + tableName + " ADD COLUMN " + columnName + " " + columnType;
            jdbcTemplate.execute(addColumnQuery);
            System.out.println("Coluna criada: " + columnName + " do tipo " + columnType);
        }
    }


    @GetMapping("/buscarTodos")
    public ResponseEntity<List<Map<String, Object>>> getAllData(
            @RequestParam("tableName") String tableName,
            @RequestHeader("ConnectionToken") String connectionToken
    ) {

        DataSource dataSource = null;

        try {
            // Configuração da chave secreta para decodificar o token
            SecretKey secretKey = Keys.hmacShaKeyFor(constants.API_SECRET_KEY.getBytes());
            System.out.println(connectionToken);
            // Decodificação do token e obtenção das credenciais do BD
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(connectionToken)
                    .getBody();

            String dbType = claims.get("dbType", String.class);
            String dbHost = claims.get("dbHost", String.class);
            int dbPort = claims.get("dbPort", Integer.class);
            String dbUser = claims.get("dbUser", String.class);
            String dbPassword = claims.get("dbPassword", String.class);
            String dbName = claims.get("dbName", String.class);

            // Estabelece conexão com o banco de dados usando as credenciais
            databaseController.connectToDatabase(new DatabaseCredentials(dbType, dbHost, dbPort, dbUser, dbPassword, dbName));
            dataSource = databaseController.getDataSource();
            JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);

            // Executa a consulta SQL
            List<Map<String, Object>> result = jdbcTemplate.queryForList("SELECT * FROM " + tableName);
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        } finally{
            if(dataSource != null){
                try{
                    dataSource.getConnection().close();
                }catch (SQLException sqle){
                    sqle.printStackTrace();
                }
            }
        }
    }

//    private boolean isValidConnectionToken(String connectionToken) {
//        // Implemente a lógica de validação do token aqui
//        return true; // Retorne true se for válido, false caso contrário
//    }



    @GetMapping("/buscar/{id}")
    public ResponseEntity<Map<String, String>> getDataById(
            @PathVariable Long id,
            @RequestHeader("ConnectionToken") String connectionToken,
            @RequestParam("tableName") String tableName) {

        DataSource dataSource = null;

        try {
            // Configuração da chave secreta para decodificar o token
            SecretKey secretKey = Keys.hmacShaKeyFor(constants.API_SECRET_KEY.getBytes());
            System.out.println(connectionToken);
            // Decodificação do token e obtenção das credenciais do BD
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(connectionToken)
                    .getBody();

            String dbType = claims.get("dbType", String.class);
            String dbHost = claims.get("dbHost", String.class);
            int dbPort = claims.get("dbPort", Integer.class);
            String dbUser = claims.get("dbUser", String.class);
            String dbPassword = claims.get("dbPassword", String.class);
            String dbName = claims.get("dbName", String.class);

            // Estabelece conexão com o banco de dados usando as credenciais
            databaseController.connectToDatabase(new DatabaseCredentials(dbType, dbHost, dbPort, dbUser, dbPassword, dbName));
            dataSource = databaseController.getDataSource();
            JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
            //System.out.println(tableName);

            String queryCount = "SELECT COUNT(*) FROM " + tableName + " WHERE id = ?";
            Integer count = jdbcTemplate.queryForObject(queryCount, Integer.class, id);

            if (count == null || count == 0) {
                // Registro não encontrado
                Map<String, String> responseMap = new HashMap<>();
                responseMap.put("codeHttp", HttpStatus.NOT_FOUND.toString());
                responseMap.put("message", "Registro não encontrado.");
                responseMap.put("Status", "Failure");
                return new ResponseEntity<>(responseMap, HttpStatus.NOT_FOUND);
            }

            String query = "SELECT * FROM " + tableName + " WHERE id = " + id;

            //System.out.println(query);
            //System.out.println(id);

            List<Map<String, Object>> result = jdbcTemplate.queryForList(query);

            Map<String, String> responseMap = new HashMap<>();
            responseMap.put("codeHttp", HttpStatus.OK.toString());
            responseMap.put("message", "Registro Encontrado!");
            responseMap.put("Status", "Success");
            responseMap.put("Dados", result.toString());
            return new ResponseEntity<>(responseMap, HttpStatus.OK);

            //return ResponseEntity.ok(result.toString());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }finally{
            if(dataSource != null){
                try{
                    dataSource.getConnection().close();
                }catch (SQLException sqle){
                    sqle.printStackTrace();
                }
            }
        }
    }



    @PutMapping("/update/{id}")
    public ResponseEntity<Map<String, String>> updateFile(
            @PathVariable Long id,  // Considera o ID para atualização
            @RequestParam("file") MultipartFile file,
            @RequestParam("fileName") String fileNameInput,
            @RequestHeader("ConnectionToken") String connectionToken,
            @RequestParam("tableName") String tableName) {

        DataSource dataSource = null;

        final long MAX_FILE_SIZE = 2 * 1024 * 1024;  // Tamanho máximo do arquivo: 2MB

        try {

            // Verificação do tamanho do arquivo
            if (file.getSize() > MAX_FILE_SIZE) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                        "codeHttp", HttpStatus.BAD_REQUEST.toString(),
                        "message", "Erro! Arquivo com Tamanho Acima do Permitido!",
                        "Status", "Error"
                ));
            }

            // Decodificando o token JWT
            SecretKey secretKey = Keys.hmacShaKeyFor(constants.API_SECRET_KEY.getBytes());
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(connectionToken)
                    .getBody();

            // Recupera os detalhes do banco a partir do token
            String dbType = claims.get("dbType", String.class);
            String dbHost = claims.get("dbHost", String.class);
            int dbPort = claims.get("dbPort", Integer.class);
            String dbUser = claims.get("dbUser", String.class);
            String dbPassword = claims.get("dbPassword", String.class);
            String dbName = claims.get("dbName", String.class);

            // Estabelece a conexão com o banco de dados
            databaseController.connectToDatabase(new DatabaseCredentials(dbType, dbHost, dbPort, dbUser, dbPassword, dbName));
            dataSource = databaseController.getDataSource();
            JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);

            String query = "SELECT COUNT(*) FROM " + tableName + " WHERE auditoria_id = ?";
            Integer count = jdbcTemplate.queryForObject(query, Integer.class, id);

            if (count == null || count == 0) {
                Map<String, String> responseMap = new HashMap<>();
                responseMap.put("codeHttp", HttpStatus.NOT_FOUND.toString());
                responseMap.put("message", "Registro não encontrado.");
                responseMap.put("Status", "Failure");
                return new ResponseEntity<>(responseMap, HttpStatus.NOT_FOUND);
            }

            // Determina a extensão do arquivo
            String fileExtension = getFileExtension(file.getOriginalFilename());

            // Processamento condicional dependendo do tipo de arquivo
            if (fileExtension.equalsIgnoreCase("xml")) {
                // Converter MultipartFile para File
                File xmlFile = convertMultipartFileToFile(file);
                // Processar arquivo XML
                XmlProcessingResult processingResult = processXmlFile(xmlFile);  // Passando File para o processamento
                Element rootElement = (Element) processingResult.getRootElement();
                Map<String, String> columns = processingResult.getColumns();

                // Atualiza a tabela, criando-a se não existir
//                if (!updateTable(jdbcTemplate, dbType, tableName, columns, id)) {
//                    Map<String, String> responseMap = new LinkedHashMap<>();
//                    responseMap.put("status", HttpStatus.BAD_REQUEST.toString());
//                    responseMap.put("message", "Tabela já existente ou erro na atualização!");
//                    return new ResponseEntity<>(responseMap, HttpStatus.BAD_REQUEST);
//                }

                String fileNamePar = (fileNameInput.length() > 0) ? fileNameInput : xmlFile.getName();
                updateDataInTable(jdbcTemplate, tableName, rootElement, fileNamePar, id);

            } else if (fileExtension.equalsIgnoreCase("xlsx")) {
                // Processar arquivo XLSX
                Map<String, String> columns = processXlsxFile(file);
//                if (!updateTable(jdbcTemplate, dbType, tableName, columns, id)) {
//                    Map<String, String> responseMap = new HashMap<>();
//                    responseMap.put("status", HttpStatus.BAD_REQUEST.toString());
//                    responseMap.put("message", "Tabela já existente ou erro na atualização!");
//                    return new ResponseEntity<>(responseMap, HttpStatus.BAD_REQUEST);
//                }
                String fileNamePar = (fileNameInput.length() > 0) ? fileNameInput : file.getOriginalFilename();
                updateDataInTableXLS(jdbcTemplate, tableName, file, fileNamePar,  id);

            } else if (fileExtension.equalsIgnoreCase("zip")) {
                // Descompactar o arquivo ZIP ou RAR se necessário
                File extractedFile = extractFileIfNeeded(file);

                long totalSize = 0;

                for (File subFile : extractedFile.listFiles()) {
                    totalSize += subFile.length();
                }

                if (totalSize > MAX_FILE_SIZE) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                            "codeHttp", HttpStatus.INTERNAL_SERVER_ERROR.toString(),
                            "message", "Erro! Arquivo com Tamanho Acima do Permitido.",
                            "Status", "Error"
                    ));
                }

                // Processar arquivos extraídos
                for (File subFile : extractedFile.listFiles()) {
                    String subFileExtension = getFileExtension(subFile.getName());
                    CustomMultipartFile multipartFile = new CustomMultipartFile(subFile);

                    if (subFileExtension.equalsIgnoreCase("xml")) {
                        // Processar arquivo XML
                        XmlProcessingResult processingResult = processXmlFile(subFile);
                        Element rootElement = (Element) processingResult.getRootElement();
                        Map<String, String> columns = processingResult.getColumns();

//                        if (!updateTable(jdbcTemplate, dbType, tableName, columns, id)) {
//                            Map<String, String> responseMap = new HashMap<>();
//                            responseMap.put("status", HttpStatus.BAD_REQUEST.toString());
//                            responseMap.put("message", "Tabela já existente ou erro na atualização!");
//                            return new ResponseEntity<>(responseMap, HttpStatus.BAD_REQUEST);
//                        }

                        String fileNamePar = (fileNameInput.length() > 0) ? fileNameInput : subFile.getName();
                        updateDataInTable(jdbcTemplate, tableName, rootElement, fileNamePar, id);

                    } else if (subFileExtension.equalsIgnoreCase("xlsx")) {
                        // Processar arquivo XLSX
                        Map<String, String> columns = processXlsxFile(multipartFile);
//                        if (!updateTable(jdbcTemplate, dbType, tableName, columns, id)) {
//                            Map<String, String> responseMap = new HashMap<>();
//                            responseMap.put("status", HttpStatus.BAD_REQUEST.toString());
//                            responseMap.put("message", "Tabela já existente ou erro na atualização!");
//                            return new ResponseEntity<>(responseMap, HttpStatus.BAD_REQUEST);
//                        }

                        String fileNamePar = (fileNameInput.length() > 0) ? fileNameInput : subFile.getName();
                        updateDataInTableXLS(jdbcTemplate, tableName, multipartFile, fileNamePar, id);
                    } else {
                        return ResponseEntity.badRequest().body(Map.of("message", "Tipo de arquivo não suportado: " + subFileExtension));
                    }
                }
            } else {
                return ResponseEntity.badRequest().body(Map.of("message", "Tipo de arquivo não suportado."));
            }

            return ResponseEntity.ok(Map.of(
                    "codeHttp", HttpStatus.OK.toString(),
                    "message", "Arquivo atualizado com sucesso!",
                    "Status", "Success",
                    "id", String.valueOf(id),
                    "tableName", tableName
            ));

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "codeHttp", HttpStatus.INTERNAL_SERVER_ERROR.toString(),
                    "message", "Erro ao atualizar arquivo: " + e.getMessage(),
                    "Status", "Error"
            ));
        } finally {
            if (dataSource != null) {
                try {
                    dataSource.getConnection().close();
                } catch (SQLException sqle) {
                    sqle.printStackTrace();
                }
            }
        }
    }




    @DeleteMapping("/delete/{id}")
    public ResponseEntity<Map<String, String>> deleteData(@PathVariable Long id,
                                                          @RequestHeader("ConnectionToken") String connectionToken,
                                                          @RequestParam("tableName") String tableName){
        DataSource dataSource = null;
        Map<String, String> responseMap = new HashMap<>();

        try {
            // Verificando e validando o token JWT
            SecretKey secretKey = Keys.hmacShaKeyFor(constants.API_SECRET_KEY.getBytes());
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(connectionToken)
                    .getBody();

            // Extrair os detalhes do banco de dados do token
            String dbType = claims.get("dbType", String.class);
            String dbHost = claims.get("dbHost", String.class);
            int dbPort = claims.get("dbPort", Integer.class);
            String dbUser = claims.get("dbUser", String.class);
            String dbPassword = claims.get("dbPassword", String.class);
            String dbName = claims.get("dbName", String.class);

            // Estabelecer conexão com o banco de dados
            databaseController.connectToDatabase(new DatabaseCredentials(dbType, dbHost, dbPort, dbUser, dbPassword, dbName));
            dataSource = databaseController.getDataSource();
            JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);

            // Verificando se a tabela existe
            String queryExistsTable = "";
            int countTable = 0;

            if(dbType.equalsIgnoreCase("postgresql")){
                queryExistsTable = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = lower(?)";
                countTable = jdbcTemplate.queryForObject(queryExistsTable, new Object[]{tableName}, Integer.class);

            }

            if(dbType.equalsIgnoreCase("mysql")){
                queryExistsTable = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ? AND table_name = lower(?)";
                countTable = jdbcTemplate.queryForObject(queryExistsTable, new Object[]{dbName, tableName}, Integer.class);

            }

            if (countTable == 0) {
                responseMap.put("codeHttp", HttpStatus.NOT_FOUND.toString());
                responseMap.put("message", "A Tabela informada não existe!");
                responseMap.put("Status", "Failure");
                return new ResponseEntity<>(responseMap, HttpStatus.NOT_FOUND);
            }


            String currentValuesSql = "SELECT * FROM " + tableName + " WHERE auditoria_id = ?";
                List<Map<String, Object>> currentValuesList = jdbcTemplate.queryForList(currentValuesSql, id);

//            System.out.println("Result: " + currentValuesList);

            if(currentValuesList.isEmpty()){
                responseMap.put("codeHttp", HttpStatus.NOT_FOUND.toString());
                responseMap.put("message", "Registros não Encontrados!");
                responseMap.put("Status", "Error");
                return new ResponseEntity<>(responseMap, HttpStatus.NOT_FOUND);
            }

            String deleteQuery = "DELETE FROM " + tableName + " WHERE auditoria_id = ?";
            jdbcTemplate.update(deleteQuery, id);

            StringBuilder previousValuesTotal = new StringBuilder();
            StringBuilder newValuesTotal = new StringBuilder();

            for (Map<String, Object> currentValues : currentValuesList) {
                String previousValues = currentValues.toString(); // Valores antes da exclusão
                String newValues = "{}"; // Não há novos valores após a exclusão
                previousValuesTotal.append(previousValues);
                newValuesTotal.append(newValues);
            }

            logAudit(jdbcTemplate, "EXCLUSÃO", tableName, String.valueOf(id), previousValuesTotal.toString(), String.valueOf(newValuesTotal));


            // Resposta de sucesso
            responseMap.put("codeHttp", HttpStatus.OK.toString());
            responseMap.put("message", "Registros deletados com sucesso!");
            responseMap.put("Status", "Success");
            return new ResponseEntity<>(responseMap, HttpStatus.OK);

        } catch (Exception e) {
            e.printStackTrace();
            // Em caso de erro, retorno com a mensagem de erro
            responseMap.put("codeHttp", HttpStatus.INTERNAL_SERVER_ERROR.toString());
            responseMap.put("message", "Erro ao deletar o registro: " + e.getMessage());
            responseMap.put("Status", "Failure");
            return new ResponseEntity<>(responseMap, HttpStatus.INTERNAL_SERVER_ERROR);
        } finally {
            // Fechando a conexão com o banco de dados
            if (dataSource != null) {
                try (Connection connection = dataSource.getConnection()) {
                    connection.close();
                } catch (SQLException sqle) {
                    sqle.printStackTrace();
                }
            }
        }
    }


}

