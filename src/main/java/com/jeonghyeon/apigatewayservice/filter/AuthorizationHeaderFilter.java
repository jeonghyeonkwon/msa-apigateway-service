package com.jeonghyeon.apigatewayservice.filter;

import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    Environment env;

    public AuthorizationHeaderFilter(Environment env){
        super(Config.class);
        this.env = env;
    }

    public static class Config{

    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                return onError(exchange,"로그인 후 이용해 주세요", HttpStatus.UNAUTHORIZED);
            };
            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            System.out.println("authorizationHeader : " + authorizationHeader);
            String jwt = authorizationHeader.replace("Bearer","");
            System.out.println("jwt : " + jwt);
            if(!isJwtValid(jwt)){
                return onError(exchange,"해당 토큰값이 일치하지 않습니다",HttpStatus.UNAUTHORIZED);
            }
            return chain.filter(exchange);
        });
    }

    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;
        String subject = null;

        try{

            subject = Jwts.parser().setSigningKey(env.getProperty("token.secret"))
                    .parseClaimsJws(jwt).getBody().getSubject();
            System.out.println(subject);
        }catch (Exception ex){
            ex.printStackTrace();
            returnValue = false;
        }

        if(subject==null||subject.isEmpty()){
            returnValue = false;
        }
        return returnValue;
    }


    private Mono<Void> onError(ServerWebExchange exchange,String err, HttpStatus httpStatus){
        ServerHttpResponse response = exchange.getResponse();
        byte[] bytes = err.getBytes(StandardCharsets.UTF_8);
        DataBuffer wrap = exchange.getResponse().bufferFactory().wrap(bytes);
        response.setStatusCode(httpStatus);
        log.error(err);
        return response.writeWith(Mono.just(wrap));
    }
}
