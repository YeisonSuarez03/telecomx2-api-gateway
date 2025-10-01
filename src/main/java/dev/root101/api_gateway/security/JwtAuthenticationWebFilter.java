package dev.root101.api_gateway.security;

import dev.root101.commons.exceptions.UnauthorizedException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationWebFilter extends AuthenticationWebFilter {

    private static final String BEARER = "Bearer ";

    private final JwtAuthenticationManager jwtAuthenticationManager;
    private final String adminBasePath;

    public JwtAuthenticationWebFilter(JwtAuthenticationManager jwtAuthenticationManager,
                                      @Value("${app.admin.base-path}") String adminBasePath) {
        super(jwtAuthenticationManager);
        this.jwtAuthenticationManager = jwtAuthenticationManager;
        this.adminBasePath = adminBasePath;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        // Skip admin endpoints (they use Basic auth)
        if (path.contains(adminBasePath)) {
            return chain.filter(exchange);
        }

        // Only enforce JWT authentication for proxied/gateway routes created in routing definitions
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        if (route == null) {
            // not a proxied route (could be static resource, admin, or other endpoint) -> skip JWT enforcement
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(BEARER)) {
            throw new UnauthorizedException("User is not authenticated and must authenticate first");
        }

        // authenticate using manager (manager expects full header as credentials)
        return jwtAuthenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authHeader, authHeader))
                .flatMap(auth -> {
                    // extract principal (subject) and roles
                    String userId = auth.getPrincipal() != null ? auth.getPrincipal().toString() : null;
                    String roles = "";
                    if (auth.getAuthorities() != null) {
                        roles = String.join(",", auth.getAuthorities().stream().map(a -> a.getAuthority()).toList());
                    }

                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .header("X-User-Id", userId == null ? "" : userId)
                            .header("X-User-Roles", roles)
                            .build();

                    ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

                    return chain.filter(mutatedExchange)
                            .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
                });
    }
}
