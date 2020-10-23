package br.com.gobsio.multisession.controllers.v1;

import java.security.Principal;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.gobsio.multisession.config.cookies.SSIDCookieWrapper;
import br.com.gobsio.multisession.repositories.httpsession.HttpSessionPrincipalsRepository;
import br.com.gobsio.multisession.repositories.httpsession.HttpSessionRepository;

@RestController
@RequestMapping("/api/v1/auth_sessions")
public class AuthSessionController {

    @Autowired
    private HttpSessionRepository httpSessionRepository;

    @Autowired
    private HttpSessionPrincipalsRepository httpSessionPrincipalsRepository;

    @GetMapping(value = "/", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> sessions(Principal principal) throws Exception {
        return ResponseEntity.ok(httpSessionRepository.findAll());
    }

    @GetMapping(value = "/{ssid}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> sessionDetails(@PathVariable("ssid") String ssid, Principal principal) throws Exception {
        return ResponseEntity.ok(httpSessionRepository.findById(UUID.fromString(ssid)).orElse(null));
    }

    @GetMapping(value = "/{ssid}/principals", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> sessionPrincipals(@PathVariable("ssid") String ssid, Principal principal)
            throws Exception {
        return ResponseEntity.ok(httpSessionPrincipalsRepository.findBySessionId(UUID.fromString(ssid)));
    }

}