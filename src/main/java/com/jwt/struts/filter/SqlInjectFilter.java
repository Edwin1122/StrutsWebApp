package com.jwt.struts.filter;


import java.io.IOException;
import java.util.Enumeration;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * SQL injection filter
 * @author CSDN: seesun2012
 * @version 0.0.1-SNAPSHOT
 * @Date 2018-01-14
 */
public class SqlInjectFilter implements Filter{

    public FilterConfig config;

    @Override
    public void destroy() {
        this.config = null;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        // Get all request parameter names
        Enumeration<?> params = httpRequest.getParameterNames();

        StringBuilder sql = new StringBuilder();
        while (params.hasMoreElements()) {
            //Get the parameter name
            String name = params.nextElement().toString();
            //Get the corresponding value of the parameter
            String[] value = httpRequest.getParameterValues(name);
            for (String s : value) {
                sql.append(s);
            }
        }
        // Filtered SQL keywords can be added manually
        String sqlInjectStrList = config.getInitParameter("sqlInjectStrList");
        if (sqlValidate(sql.toString(), sqlInjectStrList)) {
            throw new IOException("Please enter a valid character");
            // redirect or jump, slightly...
        } else {
            chain.doFilter(request, response);
        }
    }

    // Verify SQL
    protected static boolean sqlValidate(String str, String sqlInjectStrList) {
        // Unified to lowercase
        str = str.toLowerCase();
        //Convert to an array
        String[] badStrs = sqlInjectStrList.split("\\|");
        for (String badStr : badStrs) {
            // search
            if (str.contains(badStr)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        config = filterConfig;
    }

}