package com.portaregistro;

import static com.portaregistro.Store.*;

import java.time.*;
import java.util.*;

import org.springframework.stereotype.Component;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.beans.factory.annotation.Value;
import org.slf4j.MDC;

@Component
public class Jobs {
    final Store s;
    final JavaMailSender mail;
    final Errors errors;
    final TransactionTemplate tx;
    @Value("${app.mail-from}")
    String from;

    Jobs(Store s, JavaMailSender mail, Errors errors, TransactionTemplate tx) {
        this.s = s;
        this.mail = mail;
        this.errors = errors;
        this.tx = tx;
    }

    @Scheduled(fixedDelayString = "${app.mail-delay:15000}")
    public void send() {
        tx.executeWithoutResult(status -> {
            var list = s.rows("SELECT * FROM outbox WHERE status='PENDING' AND next_at<=CURRENT_TIMESTAMP ORDER BY created_at LIMIT 20 FOR UPDATE SKIP LOCKED");
            for (var o : list) {
                String request = id(), t = str(o, "tenant_id"), actor = str(o, "actor_id");
                MDC.put("tenantId", t);
                MDC.put("requestId", request);
                MDC.put("feature", "NOTIFICACAO_EMAIL");
                try {
                    var m = new SimpleMailMessage();
                    m.setFrom(from);
                    m.setTo(str(o, "destination"));
                    m.setSubject(str(o, "subject"));
                    m.setText(str(o, "body"));
                    mail.send(m);
                    s.exec("UPDATE outbox SET status='SENT',body='',attempts=attempts+1 WHERE id=?", o.get("id"));
                    if (!str(o, "parcel_id").isEmpty())
                        s.audit(t, str(o, "parcel_id"), null, "EMAIL_ENVIADO", "Provedor aceitou o envio; leitura não confirmada");
                } catch (Exception e) {
                    int attempts = ((Number) o.get("attempts")).intValue() + 1;
                    s.exec("UPDATE outbox SET status=?,attempts=?,next_at=? WHERE id=?", attempts >= 5 ? "FAILED" : "PENDING", attempts, OffsetDateTime.now().plusMinutes((long) Math.pow(2, attempts)), o.get("id"));
                    errors.record(e, t.isEmpty() ? null : t, actor.isEmpty() ? null : actor, request, "NOTIFICACAO_EMAIL", "ENVIAR_EMAIL");
                } finally {
                    MDC.clear();
                }
            }
        });
    }

    @Scheduled(fixedDelayString = "${app.cleanup-delay:3600000}")
    public void cleanup() {
        tx.executeWithoutResult(status -> {
            for (var p : s.rows("SELECT * FROM parcels WHERE completed_at<? AND status IN ('COMPLETED','RETURNED','CANCELLED') AND hold_photo=FALSE AND photo_removed_at IS NULL FOR UPDATE", OffsetDateTime.now().minusDays(90))) {
                int n = s.exec("DELETE FROM media WHERE parcel_id=? AND kind='PHOTO'", p.get("id"));
                s.exec("UPDATE parcels SET photo_removed_at=CURRENT_TIMESTAMP WHERE id=?", p.get("id"));
                if (n > 0)
                    s.audit(str(p, "tenant_id"), str(p, "id"), null, "FOTO_REMOVIDA", "90 dias após encerramento; assinatura e histórico preservados");
            }
            s.exec("DELETE FROM sessions WHERE expires_at<CURRENT_TIMESTAMP");
            s.exec("DELETE FROM access_tokens WHERE expires_at<CURRENT_TIMESTAMP");
        });
    }
}
