package dev.root101.api_gateway.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

    private final JwkService jwkService;

    public JwtAuthenticationManager(JwkService jwkService) {
        this.jwkService = jwkService;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String bearer = authentication.getCredentials().toString();
        if (bearer == null || !bearer.startsWith("Bearer ")) {
            return Mono.error(new RuntimeException("Missing or invalid Authorization header"));
        }
        String token = bearer.replaceFirst("Bearer ", "");

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(token);
        } catch (ParseException e) {
            return Mono.error(new RuntimeException("Invalid JWT"));
        }

        JWSHeader header = signedJWT.getHeader();
        String kid = header.getKeyID();
        if (kid == null) {
            return Mono.error(new RuntimeException("JWT missing kid header"));
        }

        return jwkService.findRsaKeyByKeyId(kid)
                .switchIfEmpty(Mono.error(new RuntimeException("Unable to find JWK for kid: " + kid)))
                .flatMap(rsaKey -> {
                    try {
                        RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
                        JWSVerifier verifier = new RSASSAVerifier(publicKey);
                        boolean verified = signedJWT.verify(verifier);
                        if (!verified) return Mono.error(new RuntimeException("JWT signature verification failed"));

                        // extract claims
                        String sub = signedJWT.getJWTClaimsSet().getSubject();
                        Object rolesClaim = signedJWT.getJWTClaimsSet().getClaim("role");
                        Collection<SimpleGrantedAuthority> authorities = List.of();
                        if (rolesClaim != null) {
                            if (rolesClaim instanceof String s) {
                                authorities = List.of(new SimpleGrantedAuthority((s.startsWith("ROLE_") ? s : "ROLE_" + s)));
                            } else if (rolesClaim instanceof List<?> list) {
                                authorities = list.stream()
                                        .filter(i -> i != null)
                                        .map(Object::toString)
                                        .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                                        .map(SimpleGrantedAuthority::new)
                                        .collect(Collectors.toList());
                            }
                        }

                        // build Authentication containing subject as principal and authorities
                        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(sub, null, authorities);
                        return Mono.just(auth);
                    } catch (Exception e) {
                        return Mono.error(new RuntimeException("Failed to validate JWT", e));
                    }
                });
    }
}
