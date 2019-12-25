package spring.token;

import com.alibaba.fastjson.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import spring.annotation.LoginRequired;
import spring.dto.BaseCommonResult;
import spring.model.UUserMember;
import spring.model.UUserMemberExample;
import spring.service.MemberService;
import spring.utils.HttpUtils;
import spring.utils.ResultBuilder;
import spring.utils.UserInfoRedisUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.util.List;


public class AuthenticationInterceptor implements HandlerInterceptor {
    @Autowired
    private MemberService memberService;


    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        BaseCommonResult returnResult=new BaseCommonResult();
        //设置跨域--开始
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        //解决一下跨域问题
        if (httpRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
            HttpUtils.setHeader(httpRequest,httpResponse);
            return true;
        }

        // 如果不是映射到方法直接通过
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }
        HandlerMethod handlerMethod = (HandlerMethod) handler;
        Method method = handlerMethod.getMethod();

        // 判断接口是否需要登录
        LoginRequired methodAnnotation = method.getAnnotation(LoginRequired.class);
        // 有 @LoginRequired 注解，需要认证
        if (methodAnnotation != null) {
            // 执行认证
            String token = request.getHeader("token");  // 从 http 请求头中取出 token
            if (token == null) {
                returnResult.setMsg("信息已失效，请重新登录");
                returnResult.setCode(11111);
                //设置状态码
//                response.setStatus(500);
                response.setContentType("application/json;charset=UTF-8");
                //将 登录失败 信息打包成json格式返回
                response.getWriter().write(JSON.toJSONString(returnResult));
//                throw new RuntimeException("信息已失效，请重新登录");
                return false;
            }
            String userId = "";
            try {
                userId = String.valueOf(JWT.decode(token).getAudience().get(0));  // 获取 token 中的 user id
            } catch (JWTDecodeException e) {
                returnResult.setMsg("信息已失效，请重新登录");
                returnResult.setCode(11111);
                //设置状态码
//                response.setStatus(500);
                response.setContentType("application/json;charset=UTF-8");
                //将 登录失败 信息打包成json格式返回
                response.getWriter().write(JSON.toJSONString(returnResult));
//                throw new RuntimeException("信息已失效，请重新登录");
                return false;
            }
            UUserMember user = memberService.getAppUserMsg(userId);
            if (user == null) {
                returnResult.setMsg("信息已失效，请重新登录");
                returnResult.setCode(11111);
                //设置状态码
//                response.setStatus(500);
                response.setContentType("application/json;charset=UTF-8");
                //将 登录失败 信息打包成json格式返回
                response.getWriter().write(JSON.toJSONString(returnResult));
//                throw new RuntimeException("信息已失效，请重新登录");
                return false;
            }
            // 验证 token
            try {
                JWTVerifier verifier =  JWT.require(Algorithm.HMAC256(user.getPassWord())).build();
                try {
                    verifier.verify(token);
                } catch (JWTVerificationException e) {
                    returnResult.setMsg("信息已失效，请重新登录");
                    returnResult.setCode(11111);
                    //设置状态码
//                    response.setStatus(500);
                    response.setContentType("application/json;charset=UTF-8");
                    //将 登录失败 信息打包成json格式返回
                    response.getWriter().write(JSON.toJSONString(returnResult));
//                throw new RuntimeException("信息已失效，请重新登录");
                    return false;
                }
            } catch (UnsupportedEncodingException ignore) {}
            request.setAttribute("currentUser", user);
            return true;
        }
        return true;
    }

    public void postHandle(HttpServletRequest request,HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {}

    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {}
}
