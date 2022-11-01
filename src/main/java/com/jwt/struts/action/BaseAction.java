package com.jwt.struts.action;

import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class BaseAction extends Action {

    @Override
    public ActionForward execute(ActionMapping mapping, ActionForm form, HttpServletRequest request, HttpServletResponse response) throws Exception {
        System.out.println("Entered execute method");
        ActionForward actionForward = null;
        try {
//                saveToken(request);
                actionForward = (ActionForward) actionExecute(mapping, form, request, response);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return actionForward;
    }

    protected abstract Object actionExecute(ActionMapping mapping, ActionForm form, HttpServletRequest request, HttpServletResponse response) throws Exception;
}
