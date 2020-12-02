<?php
#==============================================================================
# LTB Self Service Password
#
# Copyright (C) 2009 Clement OUDOT
# Copyright (C) 2009 LTB-project.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# GPL License: http://www.gnu.org/licenses/gpl.txt
#
#==============================================================================

#==============================================================================
# Configuration
#==============================================================================

# Debug mode
# true: log and display any errors or warnings (use this in configuration/testing)
# false: log only errors and do not display them (use this in production)
$debug = false;

# LDAP
$ldap_url = "ldap://directory.np.cwds.io";
$ldap_starttls = true;
$ldap_binddn = "cn=ldap search,ou=People,dc=cwds,dc=io";
$ldap_bindpw = "qkaY60vY944hu4q8zVqmlADC8n";
$ldap_base = "dc=cwds,dc=io";
$ldap_login_attribute = "uid";
$ldap_fullname_attribute = "cn";
$ldap_filter = "(&(objectClass=inetOrgPerson)($ldap_login_attribute={login}))";

# Active Directory mode
# true: use unicodePwd as password field
# false: LDAPv3 standard behavior
$ad_mode = false;
# Force account unlock when password is changed
$ad_options['force_unlock'] = true;
# Force user change password at next login
$ad_options['force_pwd_change'] = false;
# Allow user with expired password to change password
$ad_options['change_expired_password'] = true;

# Samba mode
# true: update sambaNTpassword and sambaPwdLastSet attributes too
# false: just update the password
$samba_mode = false;
# Set password min/max age in Samba attributes
#$samba_options['min_age'] = 5;
#$samba_options['max_age'] = 45;

# Shadow options - require shadowAccount objectClass
# Update shadowLastChange
$shadow_options['update_shadowLastChange'] = false;
$shadow_options['update_shadowExpire'] = false;

# Default to -1, never expire
$shadow_options['shadow_expire_days'] = -1;

# Hash mechanism for password:
# SSHA, SSHA256, SSHA384, SSHA512
# SHA, SHA256, SHA384, SHA512
# SMD5
# MD5
# CRYPT
# clear (the default)
# auto (will check the hash of current password)
# This option is not used with ad_mode = true
$hash = "CRYPT";

# Prefix to use for salt with CRYPT
$hash_options['crypt_salt_prefix'] = "$6$";
$hash_options['crypt_salt_length'] = "6";

# Local password policy
# This is applied before directory password policy
# Minimal length
$pwd_min_length = 15;
# Maximal length
$pwd_max_length = 0;
# Minimal lower characters
$pwd_min_lower = 1;
# Minimal upper characters
$pwd_min_upper = 1;
# Minimal digit characters
$pwd_min_digit = 1;
# Minimal special characters
$pwd_min_special = 1;
# Definition of special characters
$pwd_special_chars = "^a-zA-Z0-9";
# Forbidden characters
$pwd_forbidden_chars = "@%";
# Don't reuse the same password as currently
$pwd_no_reuse = true;
# Check that password is different than login
$pwd_diff_login = true;
# Complexity: number of different class of character required
$pwd_complexity = 0;
# use pwnedpasswords api v2 to securely check if the password has been on a leak
$use_pwnedpasswords = false;

# Show policy constraints message:
# always
# never
# onerror
$pwd_show_policy = "always";
# Position of password policy constraints message:
# above - the form
# below - the form
$pwd_show_policy_pos = "above";

# Who changes the password?
# Also applicable for question/answer save
# user: the user itself
# manager: the above binddn
$who_change_password = "user";

## Standard change
# Use standard change form?
$use_change = true;

## SSH Key Change
# Allow changing of sshPublicKey?
$change_sshkey = true;

# What attribute should be changed by the changesshkey action?
$change_sshkey_attribute = "sshPublicKey";

# Who changes the sshPublicKey attribute?
# Also applicable for question/answer save
# user: the user itself
# manager: the above binddn
$who_change_sshkey = "user";

# Notify users anytime their sshPublicKey is changed
## Requires mail configuration below
$notify_on_sshkey_change = true;

## Questions/answers
# Use questions/answers?
# true (default)
# false
$use_questions = false;

# Answer attribute should be hidden to users!
$answer_objectClass = "extensibleObject";
$answer_attribute = "info";

# Extra questions (built-in questions are in lang/$lang.inc.php)
#$messages['questions']['ice'] = "What is your favorite ice cream flavor?";

## Token
# Use tokens?
# true (default)
# false
$use_tokens = true;
# Crypt tokens?
# true (default)
# false
$crypt_tokens = true;
# Token lifetime in seconds
$token_lifetime = "3600";

## Mail
# LDAP mail attribute
$mail_attribute = "mail";
# Get mail address directly from LDAP (only first mail entry)
# and hide mail input field
# default = false
$mail_address_use_ldap = true;
# Who the email should come from
$mail_from = "CWDSDevOpsEngineering@osi.ca.gov";
$mail_from_name = "Self Service Password";
$mail_signature = "";
# Notify users anytime their password is changed
$notify_on_change = true;
# PHPMailer configuration (see https://github.com/PHPMailer/PHPMailer)
$mail_sendmailpath = '/usr/sbin/sendmail';
$mail_protocol = 'smtp';
$mail_smtp_debug = 0;
$mail_debug_format = 'html';
$mail_smtp_host = 'email-smtp.us-west-2.amazonaws.com';
$mail_smtp_auth = true;
$mail_smtp_user = "AKIASCGHSNZVFF2NHSP3";
$mail_smtp_pass = "BPrexwGUfMYjZgINvWpa+uzk/JpVgZQ7gjz+Xjx2mJWV";
$mail_smtp_port = 25;
$mail_smtp_timeout = 30;
$mail_smtp_keepalive = false;
$mail_smtp_secure = 'tls';
$mail_smtp_autotls = true;
$mail_contenttype = 'text/plain';
$mail_wordwrap = 0;
$mail_charset = 'utf-8';
$mail_priority = 3;
$mail_newline = PHP_EOL;

## SMS
# Use sms
$use_sms = false;
# SMS method (mail, api)
$sms_method = "mail";
$sms_api_lib = "lib/smsapi.inc.php";
# GSM number attribute
$sms_attribute = "mobile";
# Partially hide number
$sms_partially_hide_number = true;
# Send SMS mail to address
$smsmailto = "{sms_attribute}@service.provider.com";
# Subject when sending email to SMTP to SMS provider
$smsmail_subject = "Provider code";
# Message
$sms_message = "{smsresetmessage} {smstoken}";
# Remove non digit characters from GSM number
$sms_sanitize_number = false;
# Truncate GSM number
$sms_truncate_number = false;
$sms_truncate_number_length = 10;
# SMS token length
$sms_token_length = 6;
# Max attempts allowed for SMS token
$max_attempts = 3;

# Encryption, decryption keyphrase, required if $crypt_tokens = true
# Please change it to anything long, random and complicated, you do not have to remember it
# Changing it will also invalidate all previous tokens and SMS codes
$keyphrase = "v6k1tOPquztZ1laXM7TEDZrYOHyZnIzqrNPt8Bo5HXf6nODub8cQ9cl9GfuU1JjiKCzlUsJSUqVsxkNxds8M2Tenoxl9X4lPE";

# Reset URL (if behind a reverse proxy)
#$reset_url = $_SERVER['HTTP_X_FORWARDED_PROTO'] . "://" . $_SERVER['X-FORWARDED-FOR'] . $_SERVER['SCRIPT_NAME'];
$reset_url = "https://selfpass.cwds.io/";

# Display help messages
$show_help = true;

# Default language
$lang = "en";

# List of authorized languages. If empty, all language are allowed.
# If not empty and the user's browser language setting is not in that list, language from $lang will be used.
$allowed_lang = array();

# Display menu on top
$show_menu = true;

# Logo
$logo = "images/CWDS-Logo.png";

# Background image
#$background_image = "images/unsplash-space.jpeg";
$background_image = "images/unsplash-clouds.jpeg";

# Where to log password resets - Make sure apache has write permission
# By default, they are logged in Apache log
$reset_request_log = "/var/log/self-service-password";

# Invalid characters in login
# Set at least "*()&|" to prevent LDAP injection
# If empty, only alphanumeric characters are accepted
$login_forbidden_chars = "*()&|";

## CAPTCHA
# Use Google reCAPTCHA (http://www.google.com/recaptcha)
$use_recaptcha = false;
# Go on the site to get public and private key
$recaptcha_publickey = "";
$recaptcha_privatekey = "";
# Customization (see https://developers.google.com/recaptcha/docs/display)
$recaptcha_theme = "light";
$recaptcha_type = "image";
$recaptcha_size = "normal";
# reCAPTCHA request method, null for default, Fully Qualified Class Name to override
# Useful when allow_url_fopen=0 ex. $recaptcha_request_method = '\ReCaptcha\RequestMethod\CurlPost';
$recaptcha_request_method = null;

## Default action
# change
# sendtoken
# sendsms
$default_action = "change";


## show ldap extended error
$show_extented_ldap_error=true;

## Extra messages
# They can also be defined in lang/ files
#$messages['passwordchangedextramessage'] = NULL;
#$messages['changehelpextramessage'] = NULL;

# Launch a posthook script after successful password change
#$posthook = "/usr/share/self-service-password/posthook.sh";
$display_posthook_error = false;

# Hide some messages to not disclose sensitive information
# These messages will be replaced by badcredentials error
$obscure_failure_messages = array("mailnomatch");

# Allow to override current settings with local configuration
if (file_exists (__DIR__ . '/config.inc.local.php')) {
  require __DIR__ . '/config.inc.local.php';
}


# Set preset login from HTTP header $header_name_preset_login
$presetLogin = "";
if (isset($header_name_preset_login)) {
  $presetLoginKey = "HTTP_".strtoupper(str_replace('-','_',$header_name_preset_login));
  if (array_key_exists($presetLoginKey, $_SERVER)) {
    $presetLogin = preg_replace("/[^a-zA-Z0-9-_@\.]+/", "", filter_var($_SERVER[$presetLoginKey], FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_HIGH));
  }
}

# Allow to override current settings with an extra configuration file, whose reference is passed in HTTP_HEADER $header_name_extra_config
if (isset($header_name_extra_config)) {
  $extraConfigKey = "HTTP_".strtoupper(str_replace('-','_',$header_name_extra_config));
  if (array_key_exists($extraConfigKey, $_SERVER)) {
    $extraConfig = preg_replace("/[^a-zA-Z0-9-_]+/", "", filter_var($_SERVER[$extraConfigKey], FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_HIGH));
    if (strlen($extraConfig) > 0 && file_exists (__DIR__ . "/config.inc.".$extraConfig.".php")) {
      require  __DIR__ . "/config.inc.".$extraConfig.".php";
    }
  }
}


## config for checkexpiration batch
# to batch it call the page with curl -F login=xxxx -F password=yyyy

# allow this functionality
$use_checkexpiration=true;

$ldap_defaultpolicydn="cn=passwordDefault,ou=Policies," . $ldap_base;
$ldap_admingroupdn="cn=DevOps,ou=Group," . $ldap_base;

# if pwdExpireWarning is not define in the default policy, then define 14 days warning before expire
$expire_warning=1209600;

# if set false: then send mail, 1st day of warning, last day of warning and 1st day of expire
$expire_always_mail = true;

# message They can also be defined in lang/ files
$messages['emptyexpireform'] = "Checking password expiration for all users";
$messages["expirehelp"] = "Only administrator can run this page";
$messages['checkexpiration'] = "Check expiration of passwords";
$messages['expirechecked'] = "The password expiration check has been completed";
$messages['warningexpiresubject'] = "Warning - Your password will expired";
$messages['warningexpiremessage'] = "Hello {login},\n\nYour password will expired in {days} days.\nClick here to change your password:\n{url}\n\n";
$messages['alertexpiresubject'] = "Alert - Your password is expired";
$messages['alertexpiremessage'] = "Hello {login},\n\nYour password is expired since {days} days.\nClick here to reset your password:\n{url}\n\n";
?>
