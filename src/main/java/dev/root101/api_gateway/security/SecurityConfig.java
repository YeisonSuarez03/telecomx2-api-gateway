package dev.root101.api_gateway.security;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Component
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

    private final JwkService jwkService;

    public JwtAuthenticationManager(JwkService jwkService) {
        this.jwkService = jwkService;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        Object cred = authentication.getCredentials();
        if (cred == null) return Mono.error(new BadCredentialsException("Missing token"));

        String token = cred.toString();
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            String kid = signedJWT.getHeader().getKeyID();

            // Find JWK by kid, or try all if kid absent/not found
            Optional<JWK> maybeJwk = jwkService.getByKeyId(kid);
            boolean verified = false;
            JWK usedJwk = null;

            if (maybeJwk.isPresent()) {
                JWK jwk = maybeJwk.get();
                if (verifyWithJwk(signedJWT, jwk)) {
                    verified = true;
                    usedJwk = jwk;
                }
            } else {
                for (JWK jwk : jwkService.getJwkSet().getKeys()) {
                    if (verifyWithJwk(signedJWT, jwk)) {
                        verified = true;
                        usedJwk = jwk;
                        break;
                    }
                }
            }

            if (!verified) return Mono.error(new BadCredentialsException("JWT signature verification failed"));

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            Date exp = claims.getExpirationTime();
            if (exp == null || new Date().after(exp)) {
                return Mono.error(new BadCredentialsException("Token expired"));
            }

            String subject = claims.getSubject();
            if (subject == null || subject.isBlank()) {
                return Mono.error(new BadCredentialsException("Token missing subject"));
            }

            // Extract role(s). Accept "role" (string) or "roles" (array) or "roles" string
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            Object roleClaim = claims.getClaim("role");
            if (roleClaim == null) roleClaim = claims.getClaim("roles");
            if (roleClaim != null) {
                if (roleClaim instanceof List) {
                    ((List<?>) roleClaim).forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r.toString())));
                } else {
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + roleClaim.toString()));
                }
            }

            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(subject, token, authorities);
            return Mono.just(auth);

        } catch (BadCredentialsException ex) {
            return Mono.error(ex);
        } catch (Exception e) {
            return Mono.error(new BadCredentialsException("Invalid JWT", e));
        }
    }

    private boolean verifyWithJwk(SignedJWT signedJWT, JWK jwk) {
        try {
            if (!(jwk instanceof RSAKey)) return false;
            RSAKey rsa = (RSAKey) jwk;
            RSAPublicKey pub = rsa.toRSAPublicKey();
            JWSVerifier verifier = new RSASSAVerifier(pub);
            return signedJWT.verify(verifier);
        } catch (Exception e) {
            return false;
        }
    }
}