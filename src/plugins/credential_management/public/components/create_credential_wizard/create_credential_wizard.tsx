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
import { withRouter, RouteComponentProps } from 'react-router-dom';
import { 
  EuiHorizontalRule,
  EuiGlobalToastList,
  EuiGlobalToastListToast,
  EuiForm,
  EuiDescribedFormGroup,
  EuiFormRow,
  EuiFieldText,
  EuiSelect,
  EuiLink,
  EuiFilePicker,
  EuiButton,
  EuiPageContent
} from '@elastic/eui';
import { DocLinksStart } from 'src/core/public';
import { getCreateBreadcrumbs } from '../breadsrumbs';
import { CredentialManagmentContextValue } from '../../types';
import { Header } from './components/header';
import { context as contextType } from '../../../../opensearch_dashboards_react/public';

interface CreateCredentialWizardState {
  credentialName: string;
  credentialType: string;
  user_name: string,
  password: string,
  remoteClustersExist: boolean;
  toasts: EuiGlobalToastListToast[];
  docLinks: DocLinksStart;
}

export class CreateCredentialWizard extends React.Component<
  RouteComponentProps,
  CreateCredentialWizardState
> {

  static contextType = contextType;
  public readonly context!: CredentialManagmentContextValue;

  constructor(props: RouteComponentProps, context: CredentialManagmentContextValue) {
    super(props, context);

    context.services.setBreadcrumbs(getCreateBreadcrumbs());

    this.state = {
      credentialName: '',
      credentialType: 'basic_auth',
      user_name: '',
      password: '',
      remoteClustersExist: false,
      toasts: [],
      docLinks: context.services.docLinks,
    };
  }

  renderHeader() {
    const { docLinks } = this.state;

    return (
      <Header
        // prompt={indexPatternCreationType.renderPrompt()}
        // indexPatternName={indexPatternCreationType.getIndexPatternName()}
        // isBeta={indexPatternCreationType.getIsBeta()}
        docLinks={docLinks}
      />
    );
  }

  // TODO: Add conditional rendering
  renderContent() {
    const header = this.renderHeader();

    return (
      <EuiPageContent>
        {header}
        <EuiHorizontalRule />
        <EuiForm component="form">
          <EuiDescribedFormGroup
            title={<h3>Credential Name</h3>}
            description={
              <p>
                The name of credential that you want to create
              </p>
            }
          >
            <EuiFormRow label="Credential Name">
              <EuiFieldText 
                  placeholder="Your Credential Name"
                  value={this.state.credentialName || ''}
                  onChange={(e) => this.setState({ credentialName: e.target.value })}
              />
            </EuiFormRow>
          </EuiDescribedFormGroup>
          <EuiDescribedFormGroup
            title={<h3>Credential Type</h3>}
            description={
                <div>
                <p>
                  The type of credential that you want to create{' '}
                  <EuiLink href="#/display/text">
                    <strong>Credential Types Supported</strong>
                  </EuiLink>
                </p>
                <ul>
                  <li> For 'username_password_credential' type: this type can be used for {' '}
                  credentials in format of username, password. </li>
                  <li> Ex: Opensearch basic auth </li>
                </ul>                
                 <ul>
                   <li>  For 'aws_iam_credential' type: this type can only be used for {' '}
                  aws iam credential, with aws_access_key_id, {' '}
                  aws_secret_access_key, and region as optional </li>
                </ul>
                </div>
              }
          >
            <EuiFormRow label="Credential Type">
              <EuiSelect
                onChange={(e) => this.setState({ credentialType: e.target.value})}
                options={[
                  { value: 'basic_auth', text: 'Username and Password Credential' },
                  { value: 'aws_iam_credential', text: 'AWS IAM Credential' },
                ]}
              />
            </EuiFormRow>
            <EuiFormRow label="User Name">
              <EuiFieldText 
                  placeholder="Your User Name"
                  value={this.state.user_name || ''}
                  onChange={(e) => this.setState({ user_name: e.target.value })}
              />
            </EuiFormRow>
            <EuiFormRow label="Password">
              <EuiFieldText 
                  placeholder="Your Password"
                  value={this.redact(this.state.password.length) || ''}
                  onChange={(e) => this.setState({ password: e.target.value })}
              />
            </EuiFormRow>
            <EuiFormRow label="Upload Credential File">
              <EuiFilePicker />
            </EuiFormRow>        
          </EuiDescribedFormGroup>
          <EuiButton type="submit" fill onClick={this.createCredential}>
                Create
          </EuiButton>
        </EuiForm>
      </EuiPageContent>
    );  
  }

  removeToast = (id: string) => {
    this.setState((prevState) => ({
      toasts: prevState.toasts.filter((toast) => toast.id !== id),
    }));
  };
  
  render() {
    const content = this.renderContent();
    // console.warn("wizard: ", content)

    return (
      <>
        {content}
        <EuiGlobalToastList
          toasts={this.state.toasts}
          dismissToast={({ id }) => {
            this.removeToast(id);
          }}
          toastLifeTimeMs={6000}
        />
      </>
    );
  }

  redact = (len: number) => {
     return '*'.repeat(len);
  }

  createCredential = async () => {
    const { http } = this.context.services;
    console.warn("state: ", this.state)
    try{
      // TODO: Refactor it by registering client wrapper factory
      await http.post('/api/credential_management/create', {
        body: JSON.stringify({ 
          'credential_name': this.state.credentialName,
          'credential_type': this.state.credentialType,
          'basic_auth_credential_JSON': {
            'user_name': this.state.user_name,
            'password': this.state.password
          }
        })
      }).then((res)=>{
        console.warn(res);
        console.log("Refactor it by registering client wrapper factory");
      });
    } catch (e) {
      return e;
    }
  }  
}

// TODO: Add router
export const CreateCredentialWizardWithRouter = withRouter(CreateCredentialWizard);
