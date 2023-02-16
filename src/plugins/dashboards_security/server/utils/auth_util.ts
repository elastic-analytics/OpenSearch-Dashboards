/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { OpenSearchDashboardsRequest } from 'src/core/server';
import { User } from '../auth/user';
import { userProfiles } from '../auth/types/basic/user_bank';
import { OpenIdAuthConfig } from '../auth/types/openid/openid_auth';

export const authenticate = (authBody: any): User | null => {
  const user = userProfiles.get(authBody.username);
  try {
    if (user !== undefined && user.password === authBody.password) {
      return {
        username: authBody.username,
        credentials: authBody.password,
      };
    } else {
      throw new Error('authentication exception:: User not found');
    }
  } catch (error: any) {
    throw new Error(error.message);
  }
};

export const authenticateWithToken = (
  authzHeader: string,
  idToken: string | undefined,
  idpConfig: any,
  openIdAuthConfig: OpenIdAuthConfig,
  authType: string
): User => {
  try {
    // If IdToke = null => not authenticated
    // Else: if token payload.email does not exist => insert entry
    //      else: get the user info from identity storage

    const credentials: any = {
      authzHeader,
      idToken,
    };

    if (!idToken) {
      throw new Error('authentication exception');
    } else {
      const decodedIdToken = decodeIdToken(idToken);
      if (!validateIdToken(decodedIdToken, idpConfig, openIdAuthConfig)) {
        throw new Error('authentication exception:: Invalid ID Token');
      }

      const username = decodedIdToken.email;
      const user = userProfiles.get(username);

      if (user) {
        return {
          username: user.username,
          credentials,
        };
      } else {
        // insert into user_bank, need implementation
        userProfiles.set(username, { username, password: '', authOption: authType });
        // console.log("userProfile:: ", userProfiles);
        return {
          username,
          credentials,
        };
      }
    }
  } catch (error: any) {
    throw new Error(error.message);
  }
};

const decodeIdToken = (token: string): any => {
  const parts = token.toString().split('.');
  if (parts.length !== 3) {
    throw new Error('authentication exception:: Invalid token');
  }
  const claim = JSON.parse(Buffer.from(parts[1], 'base64').toString());

  return claim;
};

const validateIdToken = (
  idToken: any,
  idpConfig: any,
  openIdAuthConfig: OpenIdAuthConfig
): boolean => {
  if (
    idToken.aud !== idpConfig.client_id ||
    idToken.iss !== openIdAuthConfig.issuer ||
    idToken.exp > Date.now()
  ) {
    return false;
  }
  return true;
};

/* Requirere implementation
  This function will get config information and preapre SAML Request
*/
export const getSamlHeader = (request: OpenSearchDashboardsRequest): any => {
  return {
    location:
      'https://cgliu.onelogin.com/trust/saml2/http-redirect/sso/62513ad7-0fb6-4ef7-8065-c7d48f5ba802?SAMLRequest=fVJNj9owFPwrke%2FGTiAhsQCJLv1AooAWtodekHFewJJjp35O2%2F33NaGrbg%2B7t6fnmfHM6M1QtqYTyz5c7SP86AFD8rs1FsXwMCe9t8JJ1CisbAFFUOKw%2FLoR2YiLzrvglDPkFeV9hkQEH7SzJFmv5mS3%2FbjZfV5vT1Wual5mQKumKuikgTROqqBlDtWkgHPTyIIk38Bj5M5JlIoCiD2sLQZpQ1zxbEx5SrP0yKciK8Q4%2F06SVcyjrQwD6xpCh4IxdTG6HzkLxl20HSnXsuB7DOzmP2M3GPVQaw8q7tCxIsvTsaynlDfn6A6aKS15kVM1rSdlk59lyTOS7P%2B28UHbWtvL%2B0Wc7yAUX47HPd3vDkeSLF%2FKeXAW%2Bxb8AfxPreDpcXM3H70bp6S5OgwiL3jKTq6DKITBO3ZCUL3X4XnIwaRCspjdRjE05Rcv%2Bf9pVBnnM%2FYaM7vfwzYaXq%2F2zmj1nHxyvpXh7TzpKB02uqbNABW9xQ6UbjTUMZYx7teDBxlgTmLRQBK2uP%2F6%2F%2BEt%2FgA%3D',
    requestId: 'ONELOGIN_95cd082e-9f96-4fe1-9fc6-85e946ebffa6',
  };
  /*
  try {
    // response is expected to be an error
    // await this.esClient.asScoped(request).callAsCurrentUser('opensearch_security.authinfo');
  } catch (error: any) {
    // the error looks like
    // wwwAuthenticateDirective:
    //   '
    //     X-Security-IdP realm="Open Distro Security"
    //     location="https://<your-auth-domain.com>/api/saml2/v1/sso?SAMLRequest=<some-encoded-string>"
    //     requestId="<request_id>"
    //   '

    // if (!error.wwwAuthenticateDirective) {
    //   throw error;
    // }

    try {
      return {
        location:
          'https://cgliu.onelogin.com/trust/saml2/http-redirect/sso/62513ad7-0fb6-4ef7-8065-c7d48f5ba802?SAMLRequest=fVJNj9owFPwrke%2FGTiAhsQCJLv1AooAWtodekHFewJJjp35O2%2F33NaGrbg%2B7t6fnmfHM6M1QtqYTyz5c7SP86AFD8rs1FsXwMCe9t8JJ1CisbAFFUOKw%2FLoR2YiLzrvglDPkFeV9hkQEH7SzJFmv5mS3%2FbjZfV5vT1Wual5mQKumKuikgTROqqBlDtWkgHPTyIIk38Bj5M5JlIoCiD2sLQZpQ1zxbEx5SrP0yKciK8Q4%2F06SVcyjrQwD6xpCh4IxdTG6HzkLxl20HSnXsuB7DOzmP2M3GPVQaw8q7tCxIsvTsaynlDfn6A6aKS15kVM1rSdlk59lyTOS7P%2B28UHbWtvL%2B0Wc7yAUX47HPd3vDkeSLF%2FKeXAW%2Bxb8AfxPreDpcXM3H70bp6S5OgwiL3jKTq6DKITBO3ZCUL3X4XnIwaRCspjdRjE05Rcv%2Bf9pVBnnM%2FYaM7vfwzYaXq%2F2zmj1nHxyvpXh7TzpKB02uqbNABW9xQ6UbjTUMZYx7teDBxlgTmLRQBK2uP%2F6%2F%2BEt%2FgA%3D',
        requestId: 'ONELOGIN_95cd082e-9f96-4fe1-9fc6-85e946ebffa6',
      };
      // const locationRegExp = /location="(.*?)"/;
      // const requestIdRegExp = /requestId="(.*?)"/;

      // const locationExecArray = locationRegExp.exec(error.wwwAuthenticateDirective);
      // const requestExecArray = requestIdRegExp.exec(error.wwwAuthenticateDirective);
      // if (locationExecArray && requestExecArray) {
      //   return {
      //     location: locationExecArray[1],
      //     requestId: requestExecArray[1],
      //   };
      // }
      throw Error('failed parsing SAML config');
    } catch (parsingError: any) {
      console.log(parsingError);
      throw new Error(parsingError);
    }
  }
  throw new Error(`Invalid SAML configuration.`);
  */
};

export const authinfo = (request: OpenSearchDashboardsRequest, headers: any = {}): any => {
  try {
    // return await this.esClient
    //   .asScoped(request)
    //   .callAsCurrentUser('opensearch_security.authinfo', {
    //     headers,
    //   });
    return {
      user: 'User [name=admin, backend_roles=[admin], requestedTenant=null]',
      user_name: 'cgliu@amazon.com',
      user_requested_tenant: null,
      remote_address: '127.0.0.1:61197',
      backend_roles: ['admin'],
      custom_attribute_names: [],
      roles: ['own_index', 'all_access'],
      tenants: { global_tenant: true, admin_tenant: true, admin: true },
      principal: null,
      peer_certificates: '0',
      sso_logout_url:
        'https://cgliu.onelogin.com/trust/saml2/http-redirect/slo/1970238?SAMLRequest=fVJda8IwFP0rJe%2BxTbt%2BGLRMcBsFpzDHHvYit02qhTRxuSnIfv1ineAGG%2BTp5Jxzzz3JDKFXR74yezO4F%2FkxSHTBqVca%2BXgzJ4PV3AB2yDX0Erlr%2BHbxvOLxJOJHa5xpjCI3kv8VgCit64wmQbWck836YbV5qtY7EFmeQ5TQRBaM3uWipRAXMRV1Clk9bfxJSPAmLXrtnHgrb4A4yEqjA%2B08FMUJjRiN2WuU87TgLHsnwdLv02lwo%2Brg3BF5GDZ71Q0To6Uy%2B05PGtOHzg7ownP%2BODzTqJWis7LxmDIhm%2BbevSBBOTtT%2BDjZllc%2FZRpQB4OOT%2BMomoW3nItg7YuolsGjsT24vxtiEzYinaDtSOWyh04thLASkZRj8Hvo4dOMsb9HXdzLYHZ5zK3n%2Bn0rLeSp3KVtFrO8TWgt68g3mwKdZg2jbZYWeV0ULYj04vNLeQV%2F%2FI3yCw%3D%3D',
    };
  } catch (error: any) {
    throw new Error(error.message);
  }
};

export const authToken = async (
  requestId: string | undefined,
  samlResponse: any,
  acsEndpoint: any | undefined = undefined
): Promise<any> => {
  const body = {
    RequestId: requestId,
    SAMLResponse: samlResponse,
    acsEndpoint,
  };
  try {
    /*
    const authToken = await this.esClient.asScoped().callAsCurrentUser('opensearch_security.authtoken', {
      body,
    });*/
    const token = {};
    return token;
  } catch (error: any) {
    // console.log(error);
    throw new Error('failed to get token');
  }
};

export const authenticateWithHeader = (
  request: OpenSearchDashboardsRequest,
  headerName: string,
  headerValue: string,
  whitelistedHeadersAndValues: any = {},
  additionalAuthHeaders: any = {}
): Promise<User> => {
  try {
    const credentials: any = {
      headerName,
      headerValue,
    };
    const headers: any = {};
    if (headerValue) {
      headers[headerName] = headerValue;
    }

    // cannot get config elasticsearch.requestHeadersWhitelist from kibana.yml file in new platfrom
    // meanwhile, do we really need to save all headers in cookie?
    const esResponse = {
      user: 'User [name=admin, backend_roles=[admin], requestedTenant=null]',
      user_name: 'cgliu@amazon.com',
      user_requested_tenant: null,
      remote_address: '127.0.0.1:61197',
      backend_roles: ['admin'],
      custom_attribute_names: [],
      roles: ['own_index', 'all_access'],
      tenants: { global_tenant: true, admin_tenant: true, admin: true },
      principal: null,
      peer_certificates: '0',
      sso_logout_url:
        'https://cgliu.onelogin.com/trust/saml2/http-redirect/slo/1970238?SAMLRequest=fVJda8IwFP0rJe%2BxTbt%2BGLRMcBsFpzDHHvYit02qhTRxuSnIfv1ineAGG%2BTp5Jxzzz3JDKFXR74yezO4F%2FkxSHTBqVca%2BXgzJ4PV3AB2yDX0Erlr%2BHbxvOLxJOJHa5xpjCI3kv8VgCit64wmQbWck836YbV5qtY7EFmeQ5TQRBaM3uWipRAXMRV1Clk9bfxJSPAmLXrtnHgrb4A4yEqjA%2B08FMUJjRiN2WuU87TgLHsnwdLv02lwo%2Brg3BF5GDZ71Q0To6Uy%2B05PGtOHzg7ownP%2BODzTqJWis7LxmDIhm%2BbevSBBOTtT%2BDjZllc%2FZRpQB4OOT%2BMomoW3nItg7YuolsGjsT24vxtiEzYinaDtSOWyh04thLASkZRj8Hvo4dOMsb9HXdzLYHZ5zK3n%2Bn0rLeSp3KVtFrO8TWgt68g3mwKdZg2jbZYWeV0ULYj04vNLeQV%2F%2FI3yCw%3D%3D',
    };
    // const esResponse = await this.esClient
    //   .asScoped(request)
    //   .callAsCurrentUser('opensearch_security.authinfo', {
    //     headers,
    //   });
    return {
      username: esResponse.user_name,
      roles: esResponse.roles,
      backendRoles: esResponse.backend_roles,
      tenants: esResponse.tenants,
      selectedTenant: esResponse.user_requested_tenant,
      credentials,
    };
  } catch (error: any) {
    throw new Error(error.message);
  }
};
