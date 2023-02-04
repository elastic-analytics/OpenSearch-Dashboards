/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

export const PLUGIN_ID = 'opensearchDashboardsSecurity';
export const PLUGIN_NAME = 'security-dashboards-plugin';

export const APP_ID_LOGIN = 'login';
export const APP_ID_CUSTOMERROR = 'customerror';
export const OPENDISTRO_SECURITY_ANONYMOUS = 'opendistro_security_anonymous';

export const API_PREFIX = '/api/v1';
export const CONFIGURATION_API_PREFIX = 'configuration';
export const API_ENDPOINT_AUTHINFO = API_PREFIX + '/auth/authinfo';
export const API_ENDPOINT_AUTHTYPE = API_PREFIX + '/auth/type';
export const LOGIN_PAGE_URI = '/app/' + APP_ID_LOGIN;
export const CUSTOM_ERROR_PAGE_URI = '/app/' + APP_ID_CUSTOMERROR;
export const API_AUTH_LOGIN = '/auth/login';
export const API_AUTH_LOGOUT = '/auth/logout';
export const OPENID_AUTH_LOGIN = '/auth/openid/login';
export const SAML_AUTH_LOGIN = '/auth/saml/login';
export const ANONYMOUS_AUTH_LOGIN = '/auth/anonymous';
export const SAML_AUTH_LOGIN_WITH_FRAGMENT = '/auth/saml/captureUrlFragment?nextUrl=%2F';

export const OPENID_AUTH_LOGOUT = '/auth/openid/logout';
export const SAML_AUTH_LOGOUT = '/auth/saml/logout';
export const ANONYMOUS_AUTH_LOGOUT = '/auth/anonymous/logout';

export const ERROR_MISSING_ROLE_PATH = '/missing-role';
export const AUTH_HEADER_NAME = 'authorization';
export const AUTH_GRANT_TYPE = 'authorization_code';
export const AUTH_RESPONSE_TYPE = 'code';

export enum AuthType {
  BASIC = 'basic',
  OPEN_ID = 'openid',
  JWT = 'jwt',
  SAML = 'saml',
  PROXY = 'proxy',
  ANONYMOUS = 'anonymous',
}
