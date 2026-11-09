package com.portaregistro;

import static com.portaregistro.Store.*;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.util.*;
import javax.imageio.*;
import javax.imageio.stream.ImageInputStream;

import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

@Component
public class Images {
    final Store s;

    Images(Store s) {
        this.s = s;
    }

    BufferedImage decode(byte[] bytes) {
        try (var stream = ImageIO.createImageInputStream(new ByteArrayInputStream(bytes))) {
            var it = ImageIO.getImageReaders(stream);
            if (!it.hasNext()) throw new Problem(400, "Formato de imagem não suportado. Use JPG ou PNG");
            var reader = it.next();
            try {
                reader.setInput(stream);
                int w = reader.getWidth(0), h = reader.getHeight(0);
                if (w < 1 || h < 1 || (long) w * h > 20000000)
                    throw new Problem(400, "Imagem muito grande: limite de 20 megapixels");
                return reader.read(0);
            } finally {
                reader.dispose();
            }
        } catch (Problem e) {
            throw e;
        } catch (Exception e) {
            throw new Problem(400, "Imagem inválida");
        }
    }

    void signature(String t, String p, String data) {
        if (!data.startsWith("data:image/png;base64,")) throw new Problem(400, "Assinatura inválida");
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(data.substring(22));
        } catch (Exception e) {
            throw new Problem(400, "Assinatura inválida");
        }
        if (raw.length > 250000) throw new Problem(400, "Assinatura muito grande");
        var img = decode(raw);
        int ink = 0;
        for (int y = 0; y < img.getHeight(); y++)
            for (int x = 0; x < img.getWidth(); x++) {
                int c = img.getRGB(x, y), a = (c >>> 24) & 255;
                if (a > 30 && (((c >> 16) & 255) + ((c >> 8) & 255) + (c & 255)) < 600) ink++;
            }
        if (ink < 30) throw new Problem(400, "A assinatura não pode estar em branco");
        save(t, p, "SIGNATURE", raw, "image/png");
    }

    void photo(String t, String p, MultipartFile file) throws IOException {
        if (file.getSize() > 8000000) throw new Problem(400, "Limite de 8 MB por foto");
        var src = decode(file.getBytes());
        int width = Math.min(1400, src.getWidth()), height = Math.max(1, (int) ((double) width / src.getWidth() * src.getHeight()));
        byte[] bytes = null;
        for (int n = 0; n < 7; n++) {
            var out = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
            var g = out.createGraphics();
            g.setColor(Color.WHITE);
            g.fillRect(0, 0, width, height);
            g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
            g.drawImage(src, 0, 0, width, height, null);
            g.dispose();
            var writer = ImageIO.getImageWritersByFormatName("jpeg").next();
            try (var os = new ByteArrayOutputStream(); var ios = ImageIO.createImageOutputStream(os)) {
                writer.setOutput(ios);
                var param = writer.getDefaultWriteParam();
                param.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
                param.setCompressionQuality(.72f);
                writer.write(null, new IIOImage(out, null, null), param);
                ios.flush();
                bytes = os.toByteArray();
            } finally {
                writer.dispose();
            }
            if (bytes.length <= 300000) break;
            width = (int) (width * .8);
            height = (int) (height * .8);
        }
        if (bytes == null || bytes.length > 300000) throw new Problem(400, "Não foi possível compactar a foto");
        s.exec("DELETE FROM media WHERE tenant_id=? AND parcel_id=? AND kind='PHOTO'", t, p);
        save(t, p, "PHOTO", bytes, "image/jpeg");
    }

    void save(String t, String p, String kind, byte[] bytes, String mime) {
        s.exec("INSERT INTO media(id,tenant_id,parcel_id,kind,bytes_base64,mime) VALUES(?,?,?,?,?,?)", id(), t, p, kind, Base64.getEncoder().encodeToString(bytes), mime);
    }
}
