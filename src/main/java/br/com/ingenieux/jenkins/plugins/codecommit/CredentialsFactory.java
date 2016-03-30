package br.com.ingenieux.jenkins.plugins.codecommit;

/*
 * Copyright (c) 2016 ingenieux Labs
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

import com.amazonaws.auth.AWSCredentialsProvider;
import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;

import java.util.Collections;
import java.util.List;

import javax.security.auth.login.CredentialNotFoundException;

import hudson.security.ACL;
import jenkins.model.Jenkins;

public class CredentialsFactory {
    public static AWSCredentialsProvider getCredentials(String credentialsId)
            throws CredentialNotFoundException {
        return lookupNamedCredential(credentialsId);
    }

    public static AmazonWebServicesCredentials lookupNamedCredential(String credentialsId)
            throws CredentialNotFoundException {
        List<AmazonWebServicesCredentials> credentialList =
                CredentialsProvider.lookupCredentials(
                        AmazonWebServicesCredentials.class, Jenkins.getInstance(), ACL.SYSTEM,
                        Collections.<DomainRequirement>emptyList());

        AmazonWebServicesCredentials cred =
                CredentialsMatchers.firstOrNull(credentialList,
                        CredentialsMatchers.allOf(
                                CredentialsMatchers.withId(credentialsId)));

        return cred;
    }
}
