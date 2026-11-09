package com.portaregistro;

import static com.portaregistro.Store.*;

import java.io.*;
import java.security.*;
import java.time.*;
import java.util.*;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.ApplicationArguments;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.slf4j.MDC;

@Component
public class Auth extends OncePerRequestFilter implements ApplicationRunner {
    final Store s;
    final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    @Value("${app.origin}")
    String origin;
    @Value("${app.cookie-secure}")
    boolean secure;
    @Value("${app.bootstrap-email}")
    String email;
    @Value("${app.bootstrap-password}")
    String password;

    public Auth(Store s) {
        this.s = s;
    }

    public void run(ApplicationArguments a) {
        if (!email.isBlank() && s.rows("SELECT id FROM accounts WHERE super_admin=TRUE").isEmpty()) {
            validPassword(password);
            s.exec("INSERT INTO accounts(id,name,email,password_hash,super_admin) VALUES(?,?,?,?,TRUE)", id(), "Administrador SaaS", email.toLowerCase(Locale.ROOT), encoder.encode(password));
        }
    }

    static void validPassword(String p) {
        if (p == null || p.length() < 12 || p.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 72)
            throw new Problem(400, "A senha deve ter pelo menos 12 caracteres e até 72 bytes");
    }

    static String token() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static String hash(String v) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(v.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    record User(String id, boolean superAdmin) {
    }

    static User user(HttpServletRequest r) {
        return (User) r.getAttribute("user");
    }

    String tenant(HttpServletRequest r) {
        String t = r.getHeader("X-Tenant-ID");
        if (t == null) throw new Problem(400, "Selecione um condomínio");
        var u = user(r);
        var tenant = s.one("SELECT * FROM tenants WHERE id=?", t);
        if (!u.superAdmin() && s.rows("SELECT id FROM memberships WHERE tenant_id=? AND account_id=? AND active=TRUE", t, u.id()).isEmpty())
            throw new Problem(403, "Sem acesso ao condomínio");
        if (!u.superAdmin() && str(tenant, "status").equals("SUSPENDED"))
            throw new Problem(403, "Acesso do condomínio suspenso");
        MDC.put("tenantId", t);
        MDC.put("tenantName", str(tenant, "name"));
        return t;
    }

    boolean staff(HttpServletRequest r, String t) {
        return user(r).superAdmin() || !s.rows("SELECT id FROM memberships WHERE tenant_id=? AND account_id=? AND active=TRUE AND role IN ('ADMIN','PORTER')", t, user(r).id()).isEmpty();
    }

    void staffOnly(HttpServletRequest r, String t) {
        if (!staff(r, t)) throw new Problem(403, "Ação exclusiva da portaria");
    }

    void admin(HttpServletRequest r, String t) {
        if (!user(r).superAdmin() && s.rows("SELECT id FROM memberships WHERE tenant_id=? AND account_id=? AND active=TRUE AND role='ADMIN'", t, user(r).id()).isEmpty())
            throw new Problem(403, "Ação exclusiva do administrador");
    }

    void superOnly(HttpServletRequest r) {
        if (!user(r).superAdmin()) throw new Problem(403, "Ação exclusiva do SaaS");
    }

    protected void doFilterInternal(HttpServletRequest r, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String requestId = id();
        MDC.put("requestId", requestId);
        MDC.put("operation", r.getMethod() + " " + r.getRequestURI());
        response.setHeader("X-Request-ID", requestId);
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Referrer-Policy", "same-origin");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
        try {
            if (r.getRequestURI().startsWith("/api/")) {
                response.setHeader("Cache-Control", "no-store");
                if (!Set.of("GET", "HEAD", "OPTIONS").contains(r.getMethod())) {
                    if (!"1".equals(r.getHeader("X-PortaRegistro"))) throw new Problem(403, "Requisição inválida");
                    String o = r.getHeader("Origin");
                    if (o != null && !origin.equals(o)) throw new Problem(403, "Origem inválida");
                }
                String raw = null;
                if (r.getCookies() != null)
                    for (Cookie c : r.getCookies()) if (c.getName().equals("PR_SESSION")) raw = c.getValue();
                if (raw != null) {
                    var rows = s.rows("SELECT a.id,a.super_admin FROM sessions x JOIN accounts a ON a.id=x.account_id WHERE x.token_hash=? AND x.expires_at>CURRENT_TIMESTAMP", hash(raw));
                    if (!rows.isEmpty()) {
                        var a = rows.get(0);
                        r.setAttribute("user", new User(str(a, "id"), Boolean.TRUE.equals(a.get("super_admin"))));
                        MDC.put("userId", str(a, "id"));
                    }
                }
                if (!Set.of("/api/auth/login", "/api/auth/recover", "/api/auth/activate", "/api/health").contains(r.getRequestURI()) && user(r) == null)
                    throw new Problem(401, "Faça login para continuar");
            }
            chain.doFilter(r, response);
        } catch (Problem p) {
            response.setStatus(p.status);
            response.setContentType("application/json");
            response.getWriter().write("{\"message\":\"" + p.getMessage() + "\",\"requestId\":\"" + requestId + "\"}");
        } finally {
            MDC.clear();
        }
    }
}
