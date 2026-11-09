package com.portaregistro;

import java.util.*;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.slf4j.*;

@RestControllerAdvice
public class Errors {
    final Store s;
    static final Logger log = LoggerFactory.getLogger(Errors.class);

    Errors(Store s) {
        this.s = s;
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<?> handle(Exception ex) {
        int status = ex instanceof Problem p ? p.status : ex instanceof DataIntegrityViolationException ? 409 : ex instanceof MaxUploadSizeExceededException ? 413 : ex instanceof HttpMessageNotReadableException ? 400 : 500;
        String msg = ex instanceof Problem ? ex.getMessage() : status == 409 ? "Registro duplicado ou vínculo inválido" : status == 413 ? "Arquivo excede o limite permitido" : status == 400 ? "Dados inválidos" : "Não foi possível concluir a operação";
        String request = Objects.toString(MDC.get("requestId"), Store.id());
        if (status == 500) {
            String operation = Objects.toString(MDC.get("operation"), "UNKNOWN");
            String feature = operation.contains("/parcels") ? "GESTAO_ENCOMENDAS" : operation.contains("/members") || operation.contains("/units") ? "CADASTROS" : operation.contains("/auth") ? "AUTENTICACAO" : operation.contains("/media") ? "FOTOS" : operation.contains("/settings") || operation.contains("/locations") ? "CONFIGURACOES" : "API";
            record(ex, Objects.toString(MDC.get("tenantId"), null), MDC.get("userId"), request, feature, operation);
        }
        return ResponseEntity.status(status).body(Map.of("code", "HTTP_" + status, "message", msg, "requestId", request));
    }

    void record(Exception ex, String t, String user, String request, String feature, String operation) {
        try {
            s.exec("INSERT INTO failures(id,tenant_id,actor_id,request_id,feature,operation,exception_type) VALUES(?,?,?,?,?,?,?)", Store.id(), t, user, request, feature, operation, ex.getClass().getSimpleName());
        } catch (Exception ignored) {
        } // Do not log provider messages or request bodies: they may contain addresses or secrets.
        String tenantName = "não identificado";
        try {
            if (t != null) tenantName = Store.str(s.one("SELECT name FROM tenants WHERE id=?", t), "name");
        } catch (Exception ignored) {
        }
        Map<String, String> previous = MDC.getCopyOfContextMap();
        try {
            if (t != null) MDC.put("tenantId", t);
            if (tenantName != null) MDC.put("tenantName", tenantName);
            if (user != null) MDC.put("userId", user);
            if (request != null) MDC.put("requestId", request);
            if (feature != null) MDC.put("feature", feature);
            if (operation != null) MDC.put("operation", operation);
            log.atError().addKeyValue("exceptionType", ex.getClass().getName()).addKeyValue("stack", Arrays.stream(ex.getStackTrace()).limit(30).map(Object::toString).toList()).log("Falha operacional");
        } finally {
            if (previous == null) MDC.clear();
            else MDC.setContextMap(previous);
        }
    }
}
