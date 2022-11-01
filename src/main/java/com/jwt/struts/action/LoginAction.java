package com.jwt.struts.action;
 
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
 
import com.jwt.struts.forms.LoginForm;
 
public class LoginAction extends BaseAction {

//    @Override
//    public ActionForward actionExecute(ActionMapping mapping, ActionForm form,
//                                       HttpServletRequest request, HttpServletResponse response)
//            throws Exception {
//        LoginForm loginForm = (LoginForm) form;
//
//        if (isTokenValid(request, true)) {
//            if (loginForm.getUserName() == null || loginForm.getPassword() == null
//                    || !loginForm.getUserName().equalsIgnoreCase("Mukesh")
//                    || !loginForm.getPassword().equals("kumar"))
//            {
//                request.setAttribute("message", "test");
//                return mapping.findForward("success");
//            } else
//                return mapping.findForward("failure");
//        } else {
//            response.sendError(HttpServletResponse.SC_FORBIDDEN);
//            return null;
//        }
//    }

    @Override
    public ActionForward actionExecute(ActionMapping mapping, ActionForm form,
                                       HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        LoginForm loginForm = (LoginForm) form;

        if (StringUtils.isBlank(loginForm.getUserName()) || StringUtils.isBlank(loginForm.getPassword())) {
            saveToken(request);
            return mapping.findForward("failure");
        } else {
            if (isTokenValid(request, true)) {
                if (!loginForm.getUserName().equalsIgnoreCase("Mukesh") || !loginForm.getPassword().equals("kumar")) {
                    request.setAttribute("message", "test");
                    return mapping.findForward("success");
                }
            } else {
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
                return null;
            }
        }

        return null;
    }
}