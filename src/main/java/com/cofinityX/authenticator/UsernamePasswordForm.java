/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.cofinityX.authenticator;

import com.cofinityX.util.Constant;
import org.jboss.logging.Logger;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.utils.StringUtil;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;


public class UsernamePasswordForm extends AbstractUsernameFormAuthenticator implements Authenticator {
    protected static ServicesLogger log;

    private static final Logger logger = Logger.getLogger(UsernamePasswordForm.class);

    public UsernamePasswordForm() {
    }

    public void action(AuthenticationFlowContext context) {
        logger.info("UsernamePasswordForm::action");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
        } else if (this.validateForm(context, formData)) {
            context.success();
        }
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.info("UsernamePasswordForm::validateForm");
        String username = formData.getFirst(Constant.USERNAME);
        String password = formData.getFirst(Constant.PASSWORD);

        logger.info("UsernamePasswordForm::email=" + username);

        if (StringUtil.isBlank(username)) {
            Response response = context.form().setAttribute(Constant.REALM, context.getRealm())
                    .setAttribute(Constant.EMAIL_FIELD_ERROR, Constant.EMAIL_NOT_FOUND)
                    .addError(new FormMessage(Constant.EMAIL_NOT_FOUND))
                    .createForm(Constant.LOGIN_FTL);
            context.challenge(response);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, response);
            context.resetFlow();
            return false;
        } else if (!Constant.EMAIL_PATTERN.matcher(username).matches()) {
            Response response = context.form().setAttribute(Constant.REALM, context.getRealm())
                    .setAttribute(Constant.EMAIL_FIELD_ERROR, Constant.INVALID_EMAIL_FORMAT)
                    .addError(new FormMessage(Constant.INVALID_EMAIL_FORMAT))
                    .createForm(Constant.LOGIN_FTL);
            context.challenge(response);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, response);
            context.resetFlow();
            return false;
        }

        if (StringUtil.isBlank(password)) {
            Response response = context.form().setAttribute(Constant.REALM, context.getRealm())
                    .setAttribute(Constant.PWD_FIELD_ERROR, Constant.PWD_NOT_FOUND)
                    .addError(new FormMessage(Constant.PWD_NOT_FOUND))
                    .createForm(Constant.LOGIN_FTL);
            context.challenge(response);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, response);
            context.resetFlow();
            return false;
        }


        return validateUserAndPassword(context, formData);
    }

    @Override
    public boolean validateUserAndPassword(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        context.clearUser();
        String username = inputData.getFirst(Constant.USERNAME);
        UserModel user = this.getUser(context, username);
        if (user == null) {
            Response response = context.form().setAttribute(Constant.REALM, context.getRealm())
                    .setAttribute(Constant.EMAIL_FIELD_ERROR, Constant.INVALID_PASSWORD)
                    .addError(new FormMessage(Constant.INVALID_PASSWORD))
                    .createForm(Constant.LOGIN_FTL);
            context.challenge(response);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, response);
            context.resetFlow();

            return false;
        }
        boolean passwordValid = this.validatePassword(context, user, inputData);
        if (!passwordValid) {
            Response response = context.form().setAttribute(Constant.REALM, context.getRealm())
                    .setAttribute(Constant.PWD_FIELD_ERROR, Constant.INVALID_PASSWORD)
                    .addError(new FormMessage(Constant.INVALID_PASSWORD))
                    .createForm(Constant.LOGIN_FTL);
            context.challenge(response);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, response);
            context.resetFlow();

            return false;
        }
        return this.validateUser(context, user, inputData);
    }

    public void authenticate(AuthenticationFlowContext context) {
        logger.info("UsernamePasswordForm::authenticate");

        MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
        String loginHint = context.getAuthenticationSession().getClientNote("login_hint");
        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());
        if (loginHint != null || rememberMeUsername != null) {
            if (loginHint != null) {
                formData.add("username", loginHint);
            } else {
                formData.add("username", rememberMeUsername);
                formData.add("rememberMe", "on");
            }
        }

        Response challengeResponse = this.challenge(context, formData);
        context.challenge(challengeResponse);
    }

    private UserModel getUser(AuthenticationFlowContext context, String username) {
        username = username.trim();
        context.getEvent().detail("username", username);
        context.getAuthenticationSession().setAuthNote("ATTEMPTED_USERNAME", username);
        UserModel user = null;

        try {
            user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
        } catch (ModelDuplicateException var6) {
            ServicesLogger.LOGGER.modelDuplicateException(var6);
            if (var6.getDuplicateFieldName() != null && var6.getDuplicateFieldName().equals("email")) {
                this.setDuplicateUserChallenge(context, "email_in_use", "emailExistsMessage", AuthenticationFlowError.INVALID_USER);
            } else {
                this.setDuplicateUserChallenge(context, "username_in_use", "usernameExistsMessage", AuthenticationFlowError.INVALID_USER);
            }
            return null;
        }
        this.testInvalidUser(context, user);
        return user;

    }

    private boolean validateUser(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> inputData) {
        if (!this.enabledUser(context, user)) {
            return false;
        } else {
            String rememberMe = (String) inputData.getFirst("rememberMe");
            boolean remember = rememberMe != null && rememberMe.equalsIgnoreCase("on");
            if (remember) {
                context.getAuthenticationSession().setAuthNote("remember_me", "true");
                context.getEvent().detail("remember_me", "true");
            } else {
                context.getAuthenticationSession().removeAuthNote("remember_me");
            }

            context.setUser(user);
            return true;
        }
    }

    public boolean requiresUser() {
        return false;
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();
        if (formData.size() > 0) {
            forms.setFormData(formData);
        }

        return forms.createLoginUsernamePassword();
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    public void close() {
    }

    static {
        log = ServicesLogger.LOGGER;
    }
}
