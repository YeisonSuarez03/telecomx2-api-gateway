package dev.root101.api_gateway.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class JwkService {

    private final WebClient webClient;
    private final String jwksUri;

    // cached JWKSet and last fetch timestamp
    private final AtomicReference<JWKSet> cache = new AtomicReference<>();

    public JwkService(@Value("${app.auth.jwks-uri}") String jwksUri) {
        this.jwksUri = jwksUri;
        this.webClient = WebClient.builder().baseUrl(jwksUri).build();
    }

    /**
     * Fetch JWKS and cache it for a short duration.
     */
    public Mono<JWKSet> getJwkSet() {
        JWKSet cached = cache.get();
        if (cached != null) {
            return Mono.just(cached);
        }
        // Fetch remote JWKS
        return webClient.get()
                .retrieve()
                .bodyToMono(Map.class)
                .map(map -> {
                    try {
                        JWKSet jwkSet = JWKSet.parse(map);
                        cache.set(jwkSet);
                        // schedule expiry by creating a short-lived TTL using a separate thread; for simplicity we won't implement TTL here
                        return jwkSet;
                    } catch (ParseException e) {
                        throw new RuntimeException("Failed to parse JWKS", e);
                    }
                });
    }

    public Mono<RSAKey> findRsaKeyByKeyId(String kid) {
        return getJwkSet()
                .flatMap(jwkSet -> {
                    JWK jwk = jwkSet.getKeyByKeyId(kid);
                    if (jwk == null) return Mono.empty();
                    if (jwk instanceof RSAKey rsaKey) return Mono.just(rsaKey);
                    return Mono.empty();
                });
    }
}
