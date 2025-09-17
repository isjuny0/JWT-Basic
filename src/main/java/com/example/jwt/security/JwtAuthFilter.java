package com.example.jwt.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        final String header = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if (header != null && header.startsWith("Bearer ")) {
            token = header.substring(7);
            if (jwtUtil.validateToken(token)) {
                username = jwtUtil.getUsernameFromToken(token);
            }
        }

        // JWT에서 추출한 사용자 정보를 바탕으로 인증 객체(Authentication)를 생성해서 Spring Security 컨텍스트에 등록하는 과정
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // UserDetails 객체에는 비밀번호, 권한, 계정 상태 등이 담겨 있음
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // UsernamePasswordAuthentication은 Authentication 인터페스의 구현체로 Spring Security에서 인증된 사용와 권한을 담는 객체
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities()
            );
            // 요청 기반으로 추가정보(IP, 세션ID 등)를 저장
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // 최종적으로 SecurityContextHolder에 인증 객체 저장
            // 컨트롤러에서 @AuthenticationPrincipal로 인증된 사용자 정보 접근 가능
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // 로그인/회원가입 엔드포인트는 필터 동작 제외
        String path = request.getRequestURI();
        return path.startsWith("/api/auth/");
    }
}
