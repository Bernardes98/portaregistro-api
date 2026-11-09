package com.portaregistro;

import static com.portaregistro.Store.*;

import java.util.*;
import java.time.*;
import java.util.concurrent.*;

import jakarta.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.beans.factory.annotation.Value;
import org.slf4j.MDC;

@RestController
@RequestMapping("/api")
public class Api {
    final Store s;
    final Auth auth;
    final Images images;
    @Value("${app.origin}")
    String origin;

    public Api(Store s, Auth auth, Images images) {
        this.s = s;
        this.auth = auth;
        this.images = images;
    }

    record Attempt(long start, int count) {
    }

    private final ConcurrentHashMap<String, Attempt> attempts = new ConcurrentHashMap<>();

    void limit(String key) {
        long now = System.currentTimeMillis();
        attempts.entrySet().removeIf(e -> now - e.getValue().start() > 900000);
        Attempt a = attempts.compute(key, (k, v) -> v == null || now - v.start() > 900000 ? new Attempt(now, 1) : new Attempt(v.start(), v.count() + 1));
        if (a.count() > 15) throw new Problem(429, "Muitas tentativas. Aguarde 15 minutos");
    }

    String email(Map<String, Object> b) {
        String e = required(b, "email", 254).toLowerCase(Locale.ROOT);
        if (!e.matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+")) throw new Problem(400, "E-mail inválido");
        return e;
    }

    void issue(String user, String tenant, String kind, String destination) {
        String raw = Auth.token();
        s.exec("INSERT INTO access_tokens(token_hash,account_id,kind,expires_at) VALUES(?,?,?,?)", Auth.hash(raw), user, kind, OffsetDateTime.now().plusHours(24));
        s.mail(tenant, null, null, destination, "PortaRegistro — Acesso à plataforma", "Acesse o link para " + (kind.equals("RESET") ? "redefinir sua senha" : "aceitar seu convite") + ":\n" + origin + "/#access=" + raw + "\nO link expira em 24 horas.");
    }

    @GetMapping("/health")
    Map<String, Object> health() {
        s.db.queryForObject("SELECT 1", Integer.class);
        return Map.of("status", "UP");
    }

    @PostMapping("/auth/login")
    Map<String, Object> login(@RequestBody Map<String, Object> b, HttpServletRequest r, HttpServletResponse response) {
        limit("login:" + r.getRemoteAddr());
        var rows = s.rows("SELECT * FROM accounts WHERE email=?", email(b));
        String supplied = required(b, "password", 200);
        if (rows.isEmpty() || str(rows.get(0), "password_hash").isEmpty() || !auth.encoder.matches(supplied, str(rows.get(0), "password_hash")))
            throw new Problem(401, "E-mail ou senha inválidos");
        var a = rows.get(0);
        String raw = Auth.token();
        s.exec("INSERT INTO sessions(token_hash,account_id,expires_at) VALUES(?,?,?)", Auth.hash(raw), str(a, "id"), OffsetDateTime.now().plusHours(12));
        response.addHeader("Set-Cookie", ResponseCookie.from("PR_SESSION", raw).httpOnly(true).secure(auth.secure).sameSite("Strict").path("/").maxAge(43200).build().toString());
        return Map.of("ok", true);
    }

    @PostMapping("/auth/logout")
    Map<String, Object> logout(HttpServletRequest r, HttpServletResponse response) {
        if (r.getCookies() != null) for (var c : r.getCookies())
            if (c.getName().equals("PR_SESSION"))
                s.exec("DELETE FROM sessions WHERE token_hash=?", Auth.hash(c.getValue()));
        response.addHeader("Set-Cookie", ResponseCookie.from("PR_SESSION", "").path("/").httpOnly(true).secure(auth.secure).sameSite("Strict").maxAge(0).build().toString());
        return Map.of("ok", true);
    }

    @PostMapping("/auth/recover")
    @Transactional
    Map<String, Object> recover(@RequestBody Map<String, Object> b, HttpServletRequest r) {
        limit("recover:" + r.getRemoteAddr());
        var rows = s.rows("SELECT * FROM accounts WHERE email=?", email(b));
        if (!rows.isEmpty()) issue(str(rows.get(0), "id"), null, "RESET", str(rows.get(0), "email"));
        return Map.of("message", "Se houver uma conta, enviaremos instruções de acesso.");
    }

    @PostMapping("/auth/activate")
    @Transactional
    Map<String, Object> activate(@RequestBody Map<String, Object> b, HttpServletRequest r) {
        limit("activate:" + r.getRemoteAddr());
        var token = s.one("SELECT * FROM access_tokens WHERE token_hash=? AND used=FALSE AND expires_at>CURRENT_TIMESTAMP FOR UPDATE", Auth.hash(required(b, "token", 200)));
        String uid = str(token, "account_id");
        var a = s.one("SELECT * FROM accounts WHERE id=?", uid);
        boolean existing = !str(a, "password_hash").isEmpty();
        String p = required(b, "password", 200);
        if (str(token, "kind").equals("INVITE") && existing) {
            if (!auth.encoder.matches(p, str(a, "password_hash")))
                throw new Problem(400, "Use a senha da conta existente ou solicite recuperação");
        } else {
            Auth.validPassword(p);
            s.exec("UPDATE accounts SET password_hash=? WHERE id=?", auth.encoder.encode(p), uid);
            s.exec("DELETE FROM sessions WHERE account_id=?", uid);
        }
        s.exec("UPDATE access_tokens SET used=TRUE WHERE account_id=?", uid);
        return Map.of("message", "Acesso confirmado. Faça login.");
    }

    @GetMapping("/me")
    Map<String, Object> me(HttpServletRequest r) {
        var u = Auth.user(r);
        return Map.of("account", s.one("SELECT id,name,email,super_admin FROM accounts WHERE id=?", u.id()), "memberships", s.rows("SELECT m.*,t.name AS tenant_name,t.status AS tenant_status FROM memberships m JOIN tenants t ON t.id=m.tenant_id WHERE account_id=? AND active=TRUE", u.id()));
    }

    @GetMapping("/saas/tenants")
    Object tenants(HttpServletRequest r) {
        auth.superOnly(r);
        return s.rows("SELECT t.*,(SELECT COUNT(*) FROM units u WHERE u.tenant_id=t.id) AS unit_count,(SELECT COALESCE(SUM(LENGTH(bytes_base64)),0) FROM media m WHERE m.tenant_id=t.id) AS stored_base64_bytes FROM tenants t ORDER BY name");
    }

    @PostMapping("/saas/tenants")
    @Transactional
    Object createTenant(@RequestBody Map<String, Object> b, HttpServletRequest r) {
        auth.superOnly(r);
        String tid = id();
        s.exec("INSERT INTO tenants(id,name,address,structure,plan,status) VALUES(?,?,?,?,?,?)", tid, required(b, "name", 160), required(b, "address", 500), required(b, "structure", 50), "PENDING", "TRIAL");
        String uid = account(required(b, "adminName", 160), email(b));
        s.exec("INSERT INTO memberships(id,tenant_id,account_id,role) VALUES(?,?,?,'ADMIN')", id(), tid, uid);
        issue(uid, tid, "INVITE", email(b));
        s.exec("INSERT INTO locations(id,tenant_id,name) VALUES(?,?,?)", id(), tid, "Prateleira A");
        s.audit(tid, null, Auth.user(r).id(), "CONDOMINIO_CRIADO", "Cadastro criado; plano comercial pendente de definição");
        return Map.of("id", tid);
    }

    @PatchMapping("/saas/tenants/{id}")
    @Transactional
    Object tenantStatus(@PathVariable String id, @RequestBody Map<String, Object> b, HttpServletRequest r) {
        auth.superOnly(r);
        String status = required(b, "status", 30);
        if (!Set.of("TRIAL", "ACTIVE", "SUSPENDED").contains(status)) throw new Problem(400, "Status inválido");
        s.one("SELECT id FROM tenants WHERE id=?", id);
        s.exec("UPDATE tenants SET status=? WHERE id=?", status, id);
        s.audit(id, null, Auth.user(r).id(), "STATUS_CONDOMINIO", status + " — " + required(b, "reason", 500));
        return Map.of("ok", true);
    }

    @GetMapping("/saas/failures")
    Object failures(HttpServletRequest r) {
        auth.superOnly(r);
        return s.rows("SELECT f.*,t.name AS tenant_name FROM failures f LEFT JOIN tenants t ON t.id=f.tenant_id ORDER BY created_at DESC LIMIT 200");
    }

    @GetMapping("/saas/failures/page")
    Object failuresPage(HttpServletRequest r, @RequestParam(defaultValue = "0") int offset, @RequestParam(defaultValue = "20") int limit) {
        auth.superOnly(r);
        if (offset < 0 || limit < 1 || limit > 100) throw new Problem(400, "Paginação inválida");
        long total = ((Number) s.db.queryForObject("SELECT COUNT(*) FROM failures", Long.class)).longValue();
        List<Map<String, Object>> items = s.rows("SELECT f.*,t.name AS tenant_name FROM failures f LEFT JOIN tenants t ON t.id=f.tenant_id ORDER BY f.created_at DESC LIMIT ? OFFSET ?", limit, offset);
        return Map.of("items", items, "total", total, "offset", offset, "limit", limit, "hasMore", offset + items.size() < total);
    }

    String account(String name, String email) {
        var existing = s.rows("SELECT id FROM accounts WHERE email=?", email);
        if (!existing.isEmpty()) return str(existing.get(0), "id");
        String uid = id();
        s.exec("INSERT INTO accounts(id,name,email) VALUES(?,?,?)", uid, name, email);
        return uid;
    }

    @GetMapping("/units")
    Object units(HttpServletRequest r) {
        String t = auth.tenant(r);
        if (auth.staff(r, t)) return s.rows("SELECT * FROM units WHERE tenant_id=? ORDER BY block_name,number", t);
        return s.rows("SELECT DISTINCT u.* FROM units u JOIN memberships m ON m.unit_id=u.id WHERE u.tenant_id=? AND m.account_id=? AND m.active=TRUE ORDER BY block_name,number", t, Auth.user(r).id());
    }

    @PostMapping("/units")
    @Transactional
    Object unit(@RequestBody Map<String, Object> b, HttpServletRequest r) {
        String t = auth.tenant(r);
        auth.admin(r, t);
        String uid = id();
        s.exec("INSERT INTO units(id,tenant_id,block_name,number) VALUES(?,?,?,?)", uid, t, required(b, "block", 60), required(b, "number", 60));
        s.audit(t, null, Auth.user(r).id(), "UNIDADE_CRIADA", uid);
        return Map.of("id", uid);
    }

    @GetMapping("/members")
    Object members(HttpServletRequest r) {
        String t = auth.tenant(r);
        auth.staffOnly(r, t);
        return s.rows("SELECT m.*,a.name,a.email,(a.password_hash IS NOT NULL) AS activated,u.block_name,u.number FROM memberships m JOIN accounts a ON a.id=m.account_id LEFT JOIN units u ON u.id=m.unit_id WHERE m.tenant_id=? ORDER BY a.name", t);
    }

    @PostMapping("/members")
    @Transactional
    Object member(@RequestBody Map<String, Object> b, HttpServletRequest r) {
        String t = auth.tenant(r);
        auth.admin(r, t);
        String role = required(b, "role", 20);
        if (!Set.of("ADMIN", "PORTER", "RESIDENT").contains(role)) throw new Problem(400, "Perfil inválido");
        String unit = null;
        if (role.equals("RESIDENT")) {
            unit = required(b, "unitId", 36);
            s.one("SELECT id FROM units WHERE id=? AND tenant_id=?", unit, t);
        }
        String uid = account(required(b, "name", 160), email(b));
        if (!s.rows("SELECT id FROM memberships WHERE tenant_id=? AND account_id=? AND role=? AND COALESCE(unit_id,'')=? AND active=TRUE", t, uid, role, Objects.toString(unit, "")).isEmpty())
            throw new Problem(409, "Vínculo já cadastrado");
        String mid = id();
        s.exec("INSERT INTO memberships(id,tenant_id,account_id,role,unit_id) VALUES(?,?,?,?,?)", mid, t, uid, role, unit);
        if (!Boolean.FALSE.equals(b.get("invite"))) issue(uid, t, "INVITE", email(b));
        s.audit(t, null, Auth.user(r).id(), "USUARIO_VINCULADO", mid + " — " + role);
        return Map.of("id", mid);
    }

    @PostMapping("/members/{id}/invite")
    @Transactional
    Object reinvite(@PathVariable String id, HttpServletRequest r) {
        String t = auth.tenant(r);
        auth.admin(r, t);
        var m = s.one("SELECT m.account_id,a.email FROM memberships m JOIN accounts a ON a.id=m.account_id WHERE m.id=? AND m.tenant_id=? AND m.active=TRUE", id, t);
        issue(str(m, "account_id"), t, "INVITE", str(m, "email"));
        s.audit(t, null, Auth.user(r).id(), "CONVITE_REENVIADO", id);
        return Map.of("ok", true);
    }

    @PatchMapping("/members/{id}")
    @Transactional
    Object disable(@PathVariable String id, @RequestBody Map<String, Object> b, HttpServletRequest r) {
        String t = auth.tenant(r);
        auth.admin(r, t);
        var m = s.one("SELECT * FROM memberships WHERE id=? AND tenant_id=? FOR UPDATE", id, t);
        if (str(m, "account_id").equals(Auth.user(r).id()))
            throw new Problem(400, "Não altere o próprio acesso nesta tela");
        s.exec("UPDATE memberships SET active=? WHERE id=?", Boolean.TRUE.equals(b.get("active")), id);
        s.audit(t, null, Auth.user(r).id(), "VINCULO_ALTERADO", id + " — " + required(b, "reason", 500));
        return Map.of("ok", true);
    }

    @GetMapping("/settings")
    Object settings(HttpServletRequest r) {
        String t = auth.tenant(r);
        return s.one("SELECT id,name,incoming_days,outgoing_days FROM tenants WHERE id=?", t);
    }

    @PatchMapping("/settings")
    @Transactional
    Object settings(@RequestBody Map<String, Object> b, HttpServletRequest r) {
        String t = auth.tenant(r);
        auth.admin(r, t);
        s.exec("UPDATE tenants SET incoming_days=?,outgoing_days=? WHERE id=?", number(b, "incomingDays", 1, 365), number(b, "outgoingDays", 1, 365), t);
        s.audit(t, null, Auth.user(r).id(), "CONFIGURACAO_ALTERADA", "Prazos de destaque atualizados");
        return Map.of("ok", true);
    }

    @GetMapping("/locations")
    Object locations(HttpServletRequest r) {
        String t = auth.tenant(r);
        auth.staffOnly(r, t);
        return s.rows("SELECT * FROM locations WHERE tenant_id=? ORDER BY name", t);
    }

    @PostMapping("/locations")
    @Transactional
    Object location(@RequestBody Map<String, Object> b, HttpServletRequest r) {
        String t = auth.tenant(r);
        auth.admin(r, t);
        String lid = id();
        s.exec("INSERT INTO locations(id,tenant_id,name) VALUES(?,?,?)", lid, t, required(b, "name", 100));
        s.audit(t, null, Auth.user(r).id(), "LOCAL_CRIADO", lid);
        return Map.of("id", lid);
    }

    @PatchMapping("/locations/{id}")
    @Transactional
    Object locationStatus(@PathVariable String id, @RequestBody Map<String, Object> b, HttpServletRequest r) {
        String t = auth.tenant(r);
        auth.admin(r, t);
        if (s.exec("UPDATE locations SET active=? WHERE id=? AND tenant_id=?", Boolean.TRUE.equals(b.get("active")), id, t) != 1)
            throw new Problem(404, "Local não encontrado");
        s.audit(t, null, Auth.user(r).id(), "LOCAL_ALTERADO", id);
        return Map.of("ok", true);
    }

    String visibility(HttpServletRequest r, String t) {
        if (auth.staff(r, t)) return "";
        return " AND p.recipient_id='" + Auth.user(r).id() + "' AND EXISTS(SELECT 1 FROM memberships m WHERE m.account_id=p.recipient_id AND m.tenant_id=p.tenant_id AND m.unit_id=p.unit_id AND m.active=TRUE AND m.created_at<=p.created_at)";
    }

    @GetMapping("/parcels/summary")
    Object parcelSummary(HttpServletRequest r) {
        String t = auth.tenant(r);
        return s.one("SELECT COUNT(*) FILTER(WHERE p.kind='INCOMING' AND p.status IN ('AVAILABLE','AWAITING_DROP')) AS incoming_pending,COUNT(*) FILTER(WHERE p.kind='OUTGOING' AND p.status IN ('AVAILABLE','AWAITING_DROP')) AS outgoing_pending FROM parcels p WHERE p.tenant_id=?" + visibility(r, t), t);
    }

    @GetMapping("/parcels")
    Object parcels(HttpServletRequest r) {
        String t = auth.tenant(r);
        return s.rows("SELECT p.*,a.name AS recipient_name,u.block_name,u.number,l.name AS location_name FROM parcels p JOIN accounts a ON a.id=p.recipient_id JOIN units u ON u.id=p.unit_id LEFT JOIN locations l ON l.id=p.location_id WHERE p.tenant_id=?" + visibility(r, t) + " ORDER BY p.created_at DESC LIMIT 500", t);
    }

    @GetMapping("/parcels/page")
    Object parcelsPage(HttpServletRequest r, @RequestParam(defaultValue = "0") int offset, @RequestParam(defaultValue = "20") int limit, @RequestParam(defaultValue = "ALL") String kind, @RequestParam(defaultValue = "") String search, @RequestParam(defaultValue = "false") boolean pickupOnly) {
        String t = auth.tenant(r);
        if (offset < 0 || limit < 1 || limit > 100) throw new Problem(400, "Paginação inválida");
        if (!Set.of("ALL", "INCOMING", "OUTGOING").contains(kind)) throw new Problem(400, "Tipo inválido");
        StringBuilder where = new StringBuilder(" WHERE p.tenant_id=?").append(visibility(r, t));
        List<Object> args = new ArrayList<>();
        args.add(t);
        if (!kind.equals("ALL")) {
            where.append(" AND p.kind=?");
            args.add(kind);
        }
        if (pickupOnly) where.append(" AND p.status='AVAILABLE' AND p.kind='INCOMING'");
        String term = search.trim();
        if (term.length() > 120) throw new Problem(400, "Busca muito longa");
        if (!term.isEmpty()) {
            where.append(" AND (p.description ILIKE ? OR a.name ILIKE ? OR u.number ILIKE ? OR u.block_name ILIKE ?)");
            String q = "%" + term + "%";
            args.addAll(List.of(q, q, q, q));
        }
        long total = ((Number) s.db.queryForObject("SELECT COUNT(*) FROM parcels p JOIN accounts a ON a.id=p.recipient_id JOIN units u ON u.id=p.unit_id" + where, Long.class, args.toArray())).longValue();
        List<Object> pageArgs = new ArrayList<>(args);
        pageArgs.add(limit);
        pageArgs.add(offset);
        List<Map<String, Object>> items = s.rows("SELECT p.*,a.name AS recipient_name,u.block_name,u.number,l.name AS location_name FROM parcels p JOIN accounts a ON a.id=p.recipient_id JOIN units u ON u.id=p.unit_id LEFT JOIN locations l ON l.id=p.location_id" + where + " ORDER BY p.created_at DESC LIMIT ? OFFSET ?", pageArgs.toArray());
        return Map.of("items", items, "total", total, "offset", offset, "limit", limit, "hasMore", offset + items.size() < total);
    }

    Map<String, Object> parcel(String id, HttpServletRequest r, boolean lock) {
        String t = auth.tenant(r);
        return s.one("SELECT p.* FROM parcels p WHERE p.id=? AND p.tenant_id=?" + visibility(r, t) + (lock ? " FOR UPDATE" : ""), id, t);
    }

    @GetMapping("/parcels/{id}")
    Object detail(@PathVariable String id, HttpServletRequest r) {
        var p = parcel(id, r, false);
        String t = str(p, "tenant_id");
        return Map.of("parcel", p, "audit", s.rows("SELECT x.*,a.name AS actor_name FROM audit x LEFT JOIN accounts a ON a.id=x.actor_id WHERE tenant_id=? AND parcel_id=? ORDER BY created_at", t, id), "media", s.rows("SELECT id,kind,mime,created_at FROM media WHERE tenant_id=? AND parcel_id=?", t, id), "notifications", s.rows("SELECT id,status,attempts,created_at FROM outbox WHERE tenant_id=? AND parcel_id=? ORDER BY created_at DESC", t, id));
    }

    @PostMapping("/parcels")
    @Transactional
    Object createParcel(@RequestBody Map<String, Object> b, HttpServletRequest r) {
        String t = auth.tenant(r), actor = Auth.user(r).id();
        boolean staff = auth.staff(r, t);
        String kind = required(b, "kind", 20);
        if (!Set.of("INCOMING", "OUTGOING").contains(kind)) throw new Problem(400, "Tipo inválido");
        if (kind.equals("INCOMING") && !staff) throw new Problem(403, "Somente porteiros registram recebimentos");
        String unit = required(b, "unitId", 36), recipient = staff ? required(b, "recipientId", 36) : actor;
        s.one("SELECT id FROM units WHERE tenant_id=? AND id=?", t, unit);
        if (s.rows("SELECT id FROM memberships WHERE tenant_id=? AND unit_id=? AND account_id=? AND role='RESIDENT' AND active=TRUE", t, unit, recipient).isEmpty())
            throw new Problem(400, "Morador não vinculado à unidade");
        String location = null;
        if (staff) {
            if (!Boolean.TRUE.equals(b.get("physicallyReceived")))
                throw new Problem(400, "Confirme o recebimento físico");
            location = optional(b, "locationId", 36);
            if (!location.isEmpty())
                s.one("SELECT id FROM locations WHERE id=? AND tenant_id=? AND active=TRUE", location, t);
            else location = null;
        }
        String authorized = kind.equals("OUTGOING") ? required(b, "authorized", 200) : "";
        String id = id();
        s.exec("INSERT INTO parcels(id,tenant_id,unit_id,recipient_id,kind,description,volumes,location_id,carrier,authorized,instructions,expected_date,status,created_by,received_by,received_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", id, t, unit, recipient, kind, optional(b, "description", 500), number(b, "volumes", 1, 99), location, optional(b, "carrier", 160), authorized, optional(b, "instructions", 1000), optional(b, "expectedDate", 10), staff ? "AVAILABLE" : "AWAITING_DROP", actor, staff ? actor : null, staff ? OffsetDateTime.now() : null);
        s.audit(t, id, actor, staff ? "RECEBIDO_PORTARIA" : "CADASTRADO_MORADOR", kind);
        if (staff && kind.equals("INCOMING"))
            notifyResident(t, id, actor, "Sua encomenda chegou", "Uma encomenda foi recebida na portaria. Consulte o PortaRegistro para detalhes.");
        return Map.of("id", id);
    }

    String optional(Map<String, Object> b, String k, int max) {
        String v = str(b, k).trim();
        if (v.length() > max) throw new Problem(400, "Texto muito longo: " + k);
        return v;
    }

    void notifyResident(String t, String id, String actor, String subject, String body) {
        var a = s.one("SELECT a.email FROM parcels p JOIN accounts a ON a.id=p.recipient_id WHERE p.id=? AND p.tenant_id=?", id, t);
        s.mail(t, id, actor, str(a, "email"), "PortaRegistro — " + subject, body + "\n" + origin);
    }

    @PostMapping("/parcels/{id}/receive")
    @Transactional
    Object receive(@PathVariable String id, @RequestBody Map<String, Object> b, HttpServletRequest r) {
        var p = parcel(id, r, true);
        String t = str(p, "tenant_id");
        auth.staffOnly(r, t);
        if (!str(p, "status").equals("AWAITING_DROP")) throw new Problem(409, "O item já foi recebido ou encerrado");
        String location = optional(b, "locationId", 36);
        if (!location.isEmpty())
            s.one("SELECT id FROM locations WHERE id=? AND tenant_id=? AND active=TRUE", location, t);
        else location = null;
        if (!Boolean.TRUE.equals(b.get("physicallyReceived"))) throw new Problem(400, "Confirme o recebimento físico");
        s.exec("UPDATE parcels SET status='AVAILABLE',location_id=?,received_by=?,received_at=CURRENT_TIMESTAMP,version=version+1 WHERE id=?", location, Auth.user(r).id(), id);
        s.audit(t, id, Auth.user(r).id(), "RECEBIDO_PORTARIA", "Recebimento físico confirmado");
        return Map.of("ok", true);
    }

    @PostMapping("/parcels/{id}/complete")
    @Transactional
    Object complete(@PathVariable String id, @RequestBody Map<String, Object> b, HttpServletRequest r) {
        var p = parcel(id, r, true);
        String t = str(p, "tenant_id"), actor = Auth.user(r).id();
        if (!str(p, "status").equals("AVAILABLE")) throw new Problem(409, "Item não disponível para retirada");
        String method = required(b, "method", 30);
        if (!Boolean.TRUE.equals(b.get("confirmed"))) throw new Problem(400, "Confirme a retirada");
        String collector;
        if (method.equals("RESIDENT")) {
            if (!str(p, "kind").equals("INCOMING") || !str(p, "recipient_id").equals(actor))
                throw new Problem(403, "Você só pode confirmar suas encomendas recebidas");
            collector = str(s.one("SELECT name FROM accounts WHERE id=?", actor), "name");
        } else if (method.equals("SIGNATURE")) {
            auth.staffOnly(r, t);
            collector = required(b, "collector", 160);
            if (str(p, "kind").equals("OUTGOING") && !Boolean.TRUE.equals(b.get("authorizationChecked")))
                throw new Problem(400, "Confira a autorização do retirante");
            String signature = required(b, "signature", 400000);
            images.signature(t, id, signature);
        } else throw new Problem(400, "Forma de retirada inválida");
        s.exec("UPDATE parcels SET status='COMPLETED',completed_at=CURRENT_TIMESTAMP,completed_by=?,collected_by=?,method=?,version=version+1 WHERE id=?", actor, collector, method, id);
        s.audit(t, id, actor, method.equals("RESIDENT") ? "RETIRADA_CONFIRMADA_MORADOR" : "RETIRADA_COM_ASSINATURA", "Retirante: " + collector);
        if (str(p, "kind").equals("OUTGOING"))
            notifyResident(t, id, actor, "Seu item foi retirado", "O item deixado na portaria foi entregue a " + collector + ".");
        return Map.of("ok", true);
    }

    @PostMapping("/parcels/{id}/reopen")
    @Transactional
    Object reopen(@PathVariable String id, @RequestBody Map<String, Object> b, HttpServletRequest r) {
        var p = parcel(id, r, true);
        String t = str(p, "tenant_id");
        auth.admin(r, t);
        if (!str(p, "status").equals("COMPLETED"))
            throw new Problem(409, "Somente retiradas concluídas podem ser reabertas");
        if (!Boolean.TRUE.equals(b.get("physicallyPresent")))
            throw new Problem(400, "Confirme que o item está na portaria");
        s.audit(t, id, Auth.user(r).id(), "RETIRADA_REVERTIDA", required(b, "reason", 1000));
        s.exec("UPDATE parcels SET status='AVAILABLE',completed_at=NULL,completed_by=NULL,collected_by=NULL,method=NULL,version=version+1 WHERE id=?", id);
        return Map.of("ok", true);
    }

    @PostMapping("/parcels/{id}/cancel")
    @Transactional
    Object cancel(@PathVariable String id, HttpServletRequest r) {
        var p = parcel(id, r, true);
        if (!str(p, "status").equals("AWAITING_DROP"))
            throw new Problem(409, "Após o recebimento, registre devolução com assinatura");
        s.exec("UPDATE parcels SET status='CANCELLED',completed_at=CURRENT_TIMESTAMP,version=version+1 WHERE id=?", id);
        s.audit(str(p, "tenant_id"), id, Auth.user(r).id(), "PEDIDO_CANCELADO", "Cancelado antes do recebimento físico");
        return Map.of("ok", true);
    }

    @PostMapping("/parcels/{id}/return")
    @Transactional
    Object returnItem(@PathVariable String id, @RequestBody Map<String, Object> b, HttpServletRequest r) {
        var p = parcel(id, r, true);
        String t = str(p, "tenant_id");
        auth.staffOnly(r, t);
        if (!str(p, "kind").equals("OUTGOING") || !str(p, "status").equals("AVAILABLE"))
            throw new Problem(409, "Item não disponível para devolução");
        images.signature(t, id, required(b, "signature", 400000));
        String collector = required(b, "collector", 160);
        s.exec("UPDATE parcels SET status='RETURNED',completed_at=CURRENT_TIMESTAMP,completed_by=?,collected_by=?,method='SIGNATURE',version=version+1 WHERE id=?", Auth.user(r).id(), collector, id);
        s.audit(t, id, Auth.user(r).id(), "DEVOLVIDO_MORADOR", "Retirante: " + collector);
        return Map.of("ok", true);
    }

    @PatchMapping("/parcels/{id}/hold")
    @Transactional
    Object hold(@PathVariable String id, @RequestBody Map<String, Object> b, HttpServletRequest r) {
        var p = parcel(id, r, true);
        auth.admin(r, str(p, "tenant_id"));
        s.exec("UPDATE parcels SET hold_photo=? WHERE id=?", Boolean.TRUE.equals(b.get("hold")), id);
        s.audit(str(p, "tenant_id"), id, Auth.user(r).id(), "RETENCAO_FOTO_ALTERADA", required(b, "reason", 500));
        return Map.of("ok", true);
    }

    @PostMapping("/parcels/{id}/photo")
    @Transactional
    Object photo(@PathVariable String id, @RequestParam MultipartFile file, HttpServletRequest r) throws Exception {
        var p = parcel(id, r, true);
        String t = str(p, "tenant_id");
        boolean staff = auth.staff(r, t);
        String status = str(p, "status");
        if (!Set.of("AVAILABLE", "AWAITING_DROP").contains(status) || (!staff && !status.equals("AWAITING_DROP")))
            throw new Problem(409, "Foto só pode ser anexada antes da conclusão; morador apenas antes de deixar o item");
        images.photo(t, id, file);
        s.audit(t, id, Auth.user(r).id(), "FOTO_ANEXADA", "Foto compactada");
        return Map.of("ok", true);
    }

    @GetMapping("/media/{id}")
    ResponseEntity<byte[]> media(@PathVariable String id, HttpServletRequest r) {
        String t = auth.tenant(r);
        var m = s.one("SELECT * FROM media WHERE id=? AND tenant_id=?", id, t);
        parcel(str(m, "parcel_id"), r, false);
        return ResponseEntity.ok().contentType(MediaType.parseMediaType(str(m, "mime"))).cacheControl(CacheControl.noStore()).body(Base64.getDecoder().decode(str(m, "bytes_base64")));
    }

    @GetMapping("/audit")
    Object audit(HttpServletRequest r) {
        String t = auth.tenant(r);
        auth.admin(r, t);
        return s.rows("SELECT x.*,a.name AS actor_name FROM audit x LEFT JOIN accounts a ON a.id=x.actor_id WHERE x.tenant_id=? ORDER BY x.created_at DESC LIMIT 500", t);
    }

    @GetMapping("/notifications")
    Object notifications(HttpServletRequest r) {
        String t = auth.tenant(r);
        auth.admin(r, t);
        return s.rows("SELECT id,parcel_id,status,attempts,created_at FROM outbox WHERE tenant_id=? ORDER BY created_at DESC LIMIT 200", t);
    }

    @PostMapping("/notifications/{id}/retry")
    @Transactional
    Object retry(@PathVariable String id, HttpServletRequest r) {
        String t = auth.tenant(r);
        auth.admin(r, t);
        var o = s.one("SELECT * FROM outbox WHERE id=? AND tenant_id=? FOR UPDATE", id, t);
        if (!str(o, "status").equals("FAILED")) throw new Problem(409, "Somente envios com falha podem ser repetidos");
        s.exec("UPDATE outbox SET status='PENDING',attempts=0,next_at=CURRENT_TIMESTAMP WHERE id=?", id);
        s.audit(t, null, Auth.user(r).id(), "EMAIL_REPROCESSADO", id);
        return Map.of("ok", true);
    }
}
