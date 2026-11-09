package com.portaregistro;

import java.nio.file.*;
import java.io.*;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.stereotype.Component;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
class Web extends OncePerRequestFilter {
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
        String path = req.getRequestURI();
        if (path.startsWith("/api/") || path.startsWith("/media/")) {
            chain.doFilter(req, res);
            return;
        }
        String file = path.equals("/") ? "index.html" : path.substring(1);
        ClassPathResource resource = new ClassPathResource("static/" + file);
        if (!resource.exists() || file.contains("..")) {
            resource = new ClassPathResource("static/index.html");
        }
        String mime = Files.probeContentType(Path.of(file));
        if (mime != null) res.setContentType(mime);
        if (file.endsWith(".webmanifest")) res.setContentType("application/manifest+json");
        try (var in = resource.getInputStream()) {
            in.transferTo(res.getOutputStream());
        }
    }
}
