<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
    
<%@ taglib prefix="bean" uri="http://struts.apache.org/tags-bean" %>
<%@ taglib uri="http://struts.apache.org/tags-html" prefix="html"%>


<%
    String message = (String)request.getAttribute("message");
    String userName = request.getParameter("userName");
%>
    
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Welcome Page</title>
</head>
<body>
<h1>Hello JavaWebTutor</h1>

<%--<%=request.getParameter("userName")  %>--%>

<%--<html:text property="userName" value="<%= userName %>" />--%>
<%= userName %>


<br/>
<%--<%=message  %>--%>
</body>
</html>