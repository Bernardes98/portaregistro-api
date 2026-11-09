package com.portaregistro;

import java.util.*;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class Store {
    final JdbcTemplate db;

    public Store(JdbcTemplate db) {
        this.db = db;
    }

    static String id() {
        return UUID.randomUUID().toString();
    }

    List<Map<String, Object>> rows(String sql, Object... args) {
        return db.queryForList(sql, args).stream().map(row -> {
            Map<String, Object> m = new LinkedHashMap<>();
            row.forEach((k, v) -> m.put(k.toLowerCase(Locale.ROOT), v));
            return m;
        }).toList();
    }

    Map<String, Object> one(String sql, Object... args) {
        var r = rows(sql, args);
        if (r.isEmpty()) throw new Problem(404, "Registro não encontrado");
        return r.get(0);
    }

    int exec(String sql, Object... args) {
        return db.update(sql, args);
    }

    static String str(Map<String, ?> m, String key) {
        return Objects.toString(m.get(key), "");
    }

    static String required(Map<String, ?> m, String key, int max) {
        String s = str(m, key).trim();
        if (s.isEmpty() || s.length() > max) throw new Problem(400, "Campo inválido: " + key);
        return s;
    }

    static int number(Map<String, ?> m, String key, int min, int max) {
        try {
            int n = Integer.parseInt(str(m, key));
            if (n < min || n > max) throw new Exception();
            return n;
        } catch (Exception e) {
            throw new Problem(400, "Número inválido: " + key);
        }
    }

    void audit(String tenant, String parcel, String actor, String event, String detail) {
        exec("INSERT INTO audit(id,tenant_id,parcel_id,actor_id,event,detail) VALUES(?,?,?,?,?,?)", id(), tenant, parcel, actor, event, detail);
    }

    void mail(String tenant, String parcel, String actor, String to, String subject, String body) {
        exec("INSERT INTO outbox(id,tenant_id,parcel_id,actor_id,destination,subject,body) VALUES(?,?,?,?,?,?,?)", id(), tenant, parcel, actor, to, subject, body);
    }
}

class Problem extends RuntimeException {
    final int status;

    Problem(int status, String message) {
        super(message);
        this.status = status;
    }
}
