package com.cofinityX.util;

import java.util.regex.Pattern;

public class Constant {

    private Constant() {

    }

    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";

    public static final String REALM = "realm";
    public static final String LOGIN_FTL = "login.ftl";
    public static final Pattern EMAIL_PATTERN = Pattern.compile("^[\\w!#$%&'*+/=?`{|}~^-]+(?:\\.[\\w!#$%&'*+/=?`{|}~^-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,6}$");


    public static final String USER_GLOBAL_ERROR = "userError";
    public static final String EMAIL_FIELD_ERROR = "emailError";
    public static final String EMAIL_NOT_FOUND = "Email-Address is required";
    public static final String INVALID_EMAIL_FORMAT = "Email-Address must be in valid format";
    public static final String PWD_FIELD_ERROR = "pwdError";
    public static final String PWD_NOT_FOUND = "Password is required";
    public static final String INVALID_PASSWORD = "Either username or password is not correct";


}
