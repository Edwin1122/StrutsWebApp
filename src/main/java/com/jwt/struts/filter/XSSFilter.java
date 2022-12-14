package com.jwt.struts.filter;


import org.apache.commons.lang.StringEscapeUtils;

import java.io.IOException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;

public class XSSFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }
 
    @Override
    public void destroy() {
    }
 
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        chain.doFilter(new XSSRequestWrapper((HttpServletRequest) request), response);
    }
 
}