package com.jwt.struts.filter;

import org.apache.commons.lang.StringEscapeUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document.OutputSettings;
import org.jsoup.safety.Safelist;
import org.owasp.esapi.ESAPI;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

 
public class XSSRequestWrapper extends HttpServletRequestWrapper {

    private final static Safelist WHITELIST = Safelist.relaxed();

    private final static OutputSettings OUTPUTSETTINGS = new OutputSettings().prettyPrint( false );

    static {
        WHITELIST.addTags("embed", "object", "param", "span", "div", "img");
        WHITELIST.addAttributes(":all", "style", "class", "id", "name");
        WHITELIST.addAttributes("object", "width", "height", "classid", "codebase");
        WHITELIST.addAttributes("param", "name", "value");
        WHITELIST.addAttributes("embed", "src", "quality", "width", "height", "allowFullScreen",
                "allowScriptAccess", "flashvars", "name", "type", "pluginspage");
    }

    public XSSRequestWrapper(HttpServletRequest servletRequest) {
        super(servletRequest);
    }
 
    @Override
    public String[] getParameterValues(String parameter) {
        String[] values = super.getParameterValues(parameter);
 
        if (values == null) {
            return null;
        }
 
        int count = values.length;
        String[] encodedValues = new String[count];
        for (int i = 0; i < count; i++) {
            encodedValues[i] = stripXSS(values[i]);
        }
 
        return encodedValues;
    }
 
    @Override
    public String getParameter(String parameter) {
        String value = super.getParameter(parameter);
 
        return stripXSS(value);
    }
 
    @Override
    public String getHeader(String name) {
        String value = super.getHeader(name);
        return stripXSS(value);
    }
 
    private String stripXSS(String value) {
        if (value != null) {
            // NOTE: It's highly recommended to use the ESAPI library and uncomment the following line to
            // avoid encoded attacks.
            value = ESAPI.encoder().canonicalize(value);
 
            // Avoid null characters
            value = value.replaceAll("", "");
 
            // Avoid anything between script tags
            Pattern scriptPattern = Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE);
//            Matcher scriptMatcher = scriptPattern.matcher(value);
//            StringBuilder builder = new StringBuilder();
//            while (scriptMatcher.find()) {
//                System.out.println(scriptMatcher.group(1));
//                builder.append(scriptMatcher.group(1));
//            }
//
//            value = builder.toString();
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid anything in a src='...' type of expression
            scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\'(.*?)\\\'", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");
 
            scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");
 
            // Remove any lonesome </script> tag
            scriptPattern = Pattern.compile("</script>", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");
 
            // Remove any lonesome <script ...> tag
            scriptPattern = Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");
 
            // Avoid eval(...) expressions
            scriptPattern = Pattern.compile("eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");
 
            // Avoid expression(...) expressions
            scriptPattern = Pattern.compile("expression\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");
 
            // Avoid javascript:... expressions
            scriptPattern = Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");
 
            // Avoid vbscript:... expressions
            scriptPattern = Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");
 
            // Avoid onload= expressions
            scriptPattern = Pattern.compile("onload(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            //Avoid SQL injection content
            Pattern sqlPattern = Pattern.compile("(‘|or|and|;|-|--|\\+|,|like|//|/|\\*|%|#|@|exec|\\(|\\))", Pattern.CASE_INSENSITIVE);
            value = sqlPattern.matcher(value).replaceAll("");

            //clean out HTML
            value = Jsoup.clean(value, "", WHITELIST, OUTPUTSETTINGS);

        }
        return value;
    }
    
    private String escapeXSS(String value) {
        if (value != null) {
            value = StringEscapeUtils.escapeJavaScript(value);
//            value = StringEscapeUtils.escapeSql(value);
            return StringEscapeUtils.escapeHtml(value);
        }

        return null;

    }
}