package study.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 이 필터에서 처음으로 해야하는 것은 Jwt Token이 있는지 체크하는 것이다.


 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter { // OncePerRequestFilter로 매 요청마다 필터를 거치게 된다.

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization"); // 요청을 하면 헤더가 토큰과 함께 패스해야한다. authorization 헤더 생성
        final String jwt;
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith("Bearer ")){ // 조건이 충족되지 않으면 추가 처리 없이 필터체인을 계속한다.
            filterChain.doFilter(request,response); // 다음 필터로 넘어감
            return;
        }

        jwt = authHeader.substring(7); // 인덱스 7로 나누는 이유는 Bearer 6, 스페이스 1 해서 7개를 분리하기 위함이다.
        userEmail = jwtService.extractUsername(jwt);//todo extract the userEmail from JWT token;
    }
}
