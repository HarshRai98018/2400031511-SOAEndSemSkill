package soa.jwtvalidation.controller;

import java.time.Instant;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Claims;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import soa.jwtvalidation.service.JwtService;

@RestController
@RequestMapping("/api")
@Tag(name = "JWT", description = "Create and validate demo JWTs")
public class AuthController {
    private final JwtService jwtService;

    public AuthController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping("/auth/token")
    @Operation(summary = "Create a demo token", description = "Demo use only; this endpoint does not authenticate a password.")
    public TokenResponse createToken(@RequestBody TokenRequest request) {
        String role = request.role() == null || request.role().isBlank() ? "USER" : request.role().toUpperCase();
        String token = jwtService.createDemoToken(request.username(), role);
        return new TokenResponse("Bearer", token, "Use this value in Swagger's Authorize dialog.");
    }

    @GetMapping("/auth/validate")
    @Operation(summary = "Validate the supplied JWT", security = @SecurityRequirement(name = "bearerAuth"),
            parameters = @Parameter(name = "Authorization", in = ParameterIn.HEADER,
                    description = "Bearer token", required = true, schema = @Schema(type = "string")),
            responses = {
                    @ApiResponse(responseCode = "200", description = "Token signature and expiration are valid"),
                    @ApiResponse(responseCode = "401", description = "Missing, malformed, expired, or invalid token", content = @Content)
            })
    public Map<String, Object> validate(Authentication authentication) {
        JwtAuthenticationToken jwtAuthentication = (JwtAuthenticationToken) authentication;
        Claims claims = jwtService.validateToken(jwtAuthentication.getToken().getTokenValue());
        return Map.of(
                "valid", true,
                "subject", claims.get("username", String.class),
                "role", claims.get("role", String.class),
                "issuedAt", claims.getIssuedAt().toInstant(),
                "expiresAt", claims.getExpiration().toInstant());
    }

    @GetMapping("/secure/profile")
    @Operation(summary = "Read the authenticated profile", security = @SecurityRequirement(name = "bearerAuth"))
    public Map<String, Object> profile(Authentication authentication) {
        return Map.of("username", authentication.getName(), "authorities", authentication.getAuthorities(),
                "authenticated", true);
    }

    @GetMapping("/health")
    @Operation(summary = "Health check")
    public Map<String, Object> health() {
        return Map.of("status", "UP", "time", Instant.now());
    }

    public record TokenRequest(String username, String role) { }
    public record TokenResponse(String tokenType, String accessToken, String instruction) { }
}
