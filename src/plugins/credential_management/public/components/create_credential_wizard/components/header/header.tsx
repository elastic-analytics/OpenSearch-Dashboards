/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Any modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

import React from 'react';

import { EuiBetaBadge, EuiSpacer, EuiTitle, EuiText, EuiCode, EuiLink } from '@elastic/eui';

import { i18n } from '@osd/i18n';
import { FormattedMessage } from '@osd/i18n/react';
import { DocLinksStart } from 'opensearch-dashboards/public';
import { useOpenSearchDashboards } from '../../../../../../opensearch_dashboards_react/public';
import { CredentialManagementContext } from '../../../../types';
// TODO: Update the header content
export const Header = ({
  isBeta = true,
  docLinks,
}: {
  isBeta?: boolean;
  docLinks: DocLinksStart;
}) => {
  const changeTitle = useOpenSearchDashboards<CredentialManagementContext>().services.chrome
    .docTitle.change;
  const createCredentialHeader = i18n.translate('credentialManagement.createIndexPatternHeader',
    {
      defaultMessage: 'Save Your Credential',
    }
  );

  changeTitle(createCredentialHeader);

  return (
    <div>
      <EuiTitle>
        <h1>
          {createCredentialHeader}
          {isBeta ? (
            <>
              {' '}
              <EuiBetaBadge
                label={i18n.translate('credentialManagement.createCredential.betaLabel', {
                  defaultMessage: 'Beta',
                })}
              />
            </>
          ) : null}
        </h1>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiText>
        <p>
          <FormattedMessage
            id="credentialManagement.createCredential.description"
            defaultMessage="A credential can be attached to multiple sources. For example, {credential} can be attached to two data sources {first} and {second}."
            values={{
              credential: <EuiCode>username-password-credential</EuiCode>,
              first: <EuiCode>os-service-log</EuiCode>,
              second: <EuiCode>os-application-log</EuiCode>,
            }}
          />
          <br />
          {/* // <HeaderBreadcrumbs /> */}
          <EuiLink
            href={docLinks.links.noDocumentation.indexPatterns.introduction}
            target="_blank"
            external
          >
            <FormattedMessage
              id="credentialManagement.createCredential.documentation"
              defaultMessage="Read documentation"
            />
          </EuiLink>
        </p>
      </EuiText>
      {prompt ? (
        <>
          <EuiSpacer size="m" />
          {prompt}
        </>
      ) : null}
    </div>
  );
};
