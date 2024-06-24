package med.voll.api.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import med.voll.api.domain.usuarios.Usuario;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    @Value("${api.security.secret}")
    private String apiSecret;

    public String generarToken(Usuario usuario) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(apiSecret);
            return JWT.create()
                    .withIssuer("API voll.med")
                    .withSubject(usuario.getUsername())
//                    .withClaim("id", usuario.getId())
                    .withExpiresAt(generarFechaExpiracion())
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            // Invalid Signing configuration / Couldn't convert Claims.
            throw new RuntimeException();
        }

    }

    public String getSubject(String tokenJWT) {
        try {
            var algoritmo = Algorithm.HMAC256(apiSecret);
            return JWT.require(algoritmo)
                    .withIssuer("API voll.med")
                    .build()
                    .verify(tokenJWT)
                    .getSubject();
        } catch (JWTVerificationException exception) {
            throw new RuntimeException("Token JWT inválido o expirado!");
        }
    }

//    public String getSubject(String token) {
//        if (token == null) {
//            throw new RuntimeException();
//        }
//        System.out.println(token);
//        DecodedJWT verifier = null;
//        try {
//            Algorithm algorithm = Algorithm.HMAC256(apiSecret); //validando firma
//            verifier = JWT.require(algorithm)
//                    .withIssuer("API voll.med")
//                    .build()
//                    .verify(token);
//            System.out.println(verifier);
//        } catch (JWTVerificationException exception) {
//            System.out.println(exception.toString());
//        }
//        if (verifier.getSubject() == null) {
//            throw new RuntimeException("Verificador inválido ");
//        }
//        return  verifier.getSubject();
//    }


    private Instant generarFechaExpiracion() {
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-06:00"));
    }

}
