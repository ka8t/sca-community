// @audit-fixture
// @rule: sql_injection_concat_java, sql_injection_format_java, unsafe_deserialization_java,
//        xxe_injection, command_injection_java, spring_csrf_disabled, spring_cors_permissive,
//        weak_crypto_java, weak_random_java, ssl_bypass_java, open_redirect_java,
//        spel_injection, verbose_exception_java, secret_logged_java,
//        db_logic_controller_java, n_plus_1_query_java, system_out_java, catch_all_exception_java
// @category: security, architecture, maintenance
// @expected: detected

package com.example.vulnerable;

import java.io.*;
import java.sql.*;
import java.util.Random;
import java.security.MessageDigest;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import javax.persistence.EntityManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
public class VulnerableController {

    private static final Logger logger = LoggerFactory.getLogger(VulnerableController.class);

    private EntityManager entityManager;

    // SQL injection par concatenation
    public void findUser(String username) throws SQLException {
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + username + "'");
    }

    // SQL injection par concatenation — multi-ligne
    public void findUserMultiline(String username) throws SQLException {
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        stmt.executeQuery(
            "SELECT * FROM users WHERE name = '" + username + "'"
        );
    }

    // SQL injection par String.format
    public void findUserFormat(String id) throws SQLException {
        String query = String.format("SELECT * FROM users WHERE id = %s", id);
        Connection conn = getConnection();
        conn.prepareStatement(query);
    }

    // SQL injection par String.format — multi-ligne
    public void findUserFormatMultiline(String id) throws SQLException {
        String query = String.format(
            "SELECT * FROM users WHERE id = %s",
            id
        );
        Connection conn = getConnection();
        conn.prepareStatement(query);
    }

    // Deserialization non securisee
    public Object deserialize(InputStream is) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(is);
        return ois.readObject();
    }

    // XXE injection
    public void parseXml(InputStream xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(xml);
    }

    // Command injection via Runtime
    public void runCommand(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd);
    }

    // Spring CSRF disabled
    public void configureSecurity(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }

    // Spring CORS permissif
    @CrossOrigin
    public String corsEndpoint() {
        return "data";
    }

    // Weak crypto MD5
    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }

    // Weak random pour token
    public String generateToken() {
        Random random = new Random();
        return "token_" + random.nextInt();
    }

    // SSL bypass
    public void setupTrust() {
        TrustAllCerts manager = new TrustAllCerts();
    }

    // Open redirect
    public void redirect(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.sendRedirect(request.getParameter("url"));
    }

    // SpEL injection
    public Object evalExpression(String userInput) {
        SpelExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        return parser.parseExpression(userInput).getValue(context);
    }

    // Verbose exception
    public void processData() {
        try {
            riskyOperation();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Secret logged
    public void authenticate(String password) {
        logger.info("Authentication attempt with password: " + password);
    }

    // DB logic in controller
    @GetMapping("/users")
    public Object getUsers() {
        return entityManager.createQuery("SELECT u FROM User u").getResultList();
    }

    // N+1 query
    public void loadOrderDetails(java.util.List<Long> orderIds) {
        for (Long id : orderIds) {
            Object order = entityManager.find(Object.class, id);
        }
    }

    // JPA native query with concatenation
    public Object findByName(String name) {
        return entityManager.createNativeQuery("SELECT * FROM users WHERE name = '" + name + "'").getSingleResult();
    }

    // MyBatis ${} interpolation
    @Select("SELECT * FROM users WHERE name = '${username}'")
    public Object findByUsername(String username) {
        return null;
    }

    // System.out
    public void debugMethod() {
        System.out.println("Debug: entering method");
    }

    private Connection getConnection() { return null; }
    private void riskyOperation() throws Exception {}
}
