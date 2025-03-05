/*
이 코드는 클라이언트 요청시 헤더에 전달되는 JWT 토큰을 처리하는 필터로,
 클라이언트가 보낸 요청에서 JWT를 추출해JWT 토큰을 검증하고,
 유효하면 인증 정보를 SecurityContext에 저장하는 역할을 해.
* */

/*<securty context>
*SecurityContext는 Spring Security에서 현재 인증된 사용자(현재로그인한 유저들)에 대한 정보를 저장하는 객체야.
*  쉽게 말해서, 로그인한 사용자에 대한 인증 정보(예: 아이디, 권한 등)를 관리하는 "저장소" 역할을 해.
*
* */

package security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import security.constrants.SecurityConstants;
import security.provider.JwtProvider;

import java.io.IOException;

@Slf4j
public class JwtRequestFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;

    public JwtRequestFilter(AuthenticationManager authenticationManager, JwtProvider jwtProvider) {
        this.authenticationManager = authenticationManager;
        this.jwtProvider = jwtProvider;
    }

    /**
     * 필터에서 수행하는 작업
     * 1. JWT 추출
     * 2. 인증 시도
     * 3. JWT 검증
     *      ⭕ 토큰이 유효하면 인증 처리 완료
     *      ❌ 토큰이 만료되면 인증 실패
     * 4. 다음 필터로 진행
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1. JWT 추출
        // 클라이언트가 보낸 요청에서 JWT를 헤더에서 추출
        String authorization = request.getHeader(SecurityConstants.TOKEN_HEADER); // 헤더에서 "Authorization" 가져오기
        log.info("authorization : " + authorization); // Authorization 헤더 출력 (디버깅 용)

        //  "Bearer {jwt}" 형식으로 헤더가 오므로, 확인하고 올바르지 않으면 바로 다음 필터로 넘어가게 함
        if (authorization == null || authorization.length() == 0 || !authorization.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            // 헤더가 없거나 "Bearer "로 시작하지 않으면, JWT가 아니므로 필터 체인의 다음 필터로 넘어감
            filterChain.doFilter(request, response);
            return;
        }

        //  JWT만 추출
        // "Bearer {jwt}"에서 "Bearer " 부분을 제거하고, 실제 JWT만 추출함
        String jwt = authorization.replace(SecurityConstants.TOKEN_PREFIX, "");

        // 2. 인증 시도 (jwt 해석해 인증 정보를 담은 객체 반환)
        // JWT를 이용해 인증 정보를 얻음
        Authentication authentication = jwtProvider.getAuthenticationToken(jwt);

        if (authentication != null && authentication.isAuthenticated()) {
            // JWT로 인증이 성공적으로 이루어졌다면, 인증 완료 로그 출력
            log.info("JWT 를 통한 인증 완료");
        }

        // 3. JWT 검증
        // JWT가 유효한지 확인 (만료되었거나 변조되었으면 false 반환)
        boolean result = jwtProvider.validateToken(jwt);

        if (result) {
            // 유효한 JWT 토큰이면 인증 완료
            log.info("유효한 JWT 토큰 입니다.");

            // SecurityContextHolder: 현재 인증된 사용자들의 정보를 담는 객체
            // 현재 인증된 사용자의 정보를 SecurityContext에 설정 (인증된 사용자로 인정)
            //authentication 이 객체는 로그인한 사용자의 정보를 담고 있어.
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        // 4. 다음 필터로 진행
        // JWT가 검증되었거나 인증이 완료되었으면, 요청을 필터 체인의 다음 필터로 넘김
        filterChain.doFilter(request, response);
    }
}


