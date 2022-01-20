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
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.AbstractIdCredentialsListBoxModel;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.eclipse.jgit.transport.RemoteConfig;
import org.eclipse.jgit.transport.URIish;
import org.jenkinsci.plugins.gitclient.GitClient;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.login.CredentialNotFoundException;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.model.Item;
import hudson.plugins.git.GitException;
import hudson.plugins.git.GitSCM;
import hudson.plugins.git.extensions.GitSCMExtension;
import hudson.plugins.git.extensions.GitSCMExtensionDescriptor;
import hudson.security.ACL;

import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
 * CodeCommit URL Helper
 */
public class CodeCommitURLHelper extends GitSCMExtension {
    private String credentialId;
    private String repositoryName;

    @DataBoundConstructor
    public CodeCommitURLHelper(String credentialId, String repositoryName) {
        this.credentialId = credentialId;
        this.repositoryName = repositoryName;
    }

    public String getCredentialId() {
        return this.credentialId;
    }

    public String getRepositoryName() {
        return this.repositoryName;
    }


    private static final class RepositoryUsernameReference {
        private final UsernamePasswordCredentialsImpl credential;

        private final String repositoryUrl;

        private final String repositoryName;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;

            if (o == null || getClass() != o.getClass()) return false;

            RepositoryUsernameReference that = (RepositoryUsernameReference) o;

            return new EqualsBuilder()
                    .append(repositoryName, that.repositoryName)
                    .isEquals();
        }

        @Override
        public int hashCode() {
            return new HashCodeBuilder(17, 37)
                    .append(repositoryName)
                    .toHashCode();
        }

        public RepositoryUsernameReference(String repositoryUrl, String repositoryName, String username, String password) {
            this.repositoryUrl = repositoryUrl;

            this.repositoryName = repositoryName;

            this.credential = new UsernamePasswordCredentialsImpl(CredentialsScope.USER, repositoryName, "codecommit-" + repositoryName, username, password);
        }

        public UsernamePasswordCredentialsImpl getCredential() {
            return credential;
        }

        public String getRepositoryUrl() {
            return repositoryUrl;
        }

        public String getRepositoryName() {
            return repositoryName;
        }
    }

    @Override
    public GitClient decorate(GitSCM scm, GitClient git) throws IOException, InterruptedException, GitException {
        try {
            for (RepositoryUsernameReference r : fetchCodeCommitRepositoryNames(scm)) {
                git.addCredentials(r.getRepositoryUrl(), r.getCredential());
            }

            return git;
        } catch (Exception e) {
            throw new GitException("Meh", e);
        }
    }

    private static final Pattern PATTERN_CODECOMMIT_REPO = Pattern.compile("^https://git-codecommit.([^\\.]+).amazonaws.com/v1/repos/(.*)$");

    private Iterable<RepositoryUsernameReference> fetchCodeCommitRepositoryNames(GitSCM scm) throws CredentialNotFoundException {
        AWSCredentialsProvider credentials = new DefaultAWSCredentialsProviderChain();

        if (isNotBlank(credentialId)) {
            credentials = CredentialsFactory.getCredentials(credentialId);

            if (null == credentials)
                throw new CredentialNotFoundException("CredentialId '" + credentialId + "' specified but not found.");
        }

        Set<RepositoryUsernameReference> results = new LinkedHashSet<RepositoryUsernameReference>();

        for (RemoteConfig cfg : scm.getRepositories()) {
            for (URIish u : cfg.getURIs()) {
                final String repositoryUrl = u.toPrivateASCIIString();
                final Matcher m = PATTERN_CODECOMMIT_REPO.matcher(repositoryUrl);

                if (m.matches()) {
                    final String awsRegion = m.group(1);
                    final String repositoryName = m.group(2);

                    String usernamePassword = new CodeCommitRequestSigner(credentials,
                            repositoryName,
                            awsRegion,
                            new Date())
                            .getPushUrl();

                    int lastIndex = usernamePassword.lastIndexOf(':');

                    String username = usernamePassword.substring(0, lastIndex);

                    String password = usernamePassword.substring(1 + lastIndex);

                    results.add(new RepositoryUsernameReference(repositoryUrl, repositoryName, username, password));
                }
            }
        }

        return results;
    }

    /**
     * Descriptor for {@link CodeCommitURLHelper}. Used as a singleton. The class is marked as
     * public so that it can be accessed from views.
     *
     * <p> See <tt>src/main/resources/hudson/plugins/hello_world/CodeCommitURLHelper/*.jelly</tt>
     * for the actual HTML fragment for the configuration screen.
     */
    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static final class DescriptorImpl extends GitSCMExtensionDescriptor {
        /**
         * In order to load the persisted global configuration, you have to call load() in the
         * constructor.
         */
        public DescriptorImpl() {
            load();
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        public String getDisplayName() {
            return "AWS CodeCommit URL Helper";
        }

        public AbstractIdCredentialsListBoxModel<?, ?> doFillCredentialIdItems(
                @AncestorInPath Item owner) {

            if (owner != null && !owner.hasPermission(Item.CONFIGURE)) {
                return new AWSCredentialsListBoxModel();
            }

            List<AmazonWebServicesCredentials> creds;
            if (owner == null) {
                // no owner (e.g. no Job), this happens on the "Configure System" page when adding a Global Library
                creds = CredentialsProvider.lookupCredentials(AmazonWebServicesCredentials.class);
            } else {
                creds = CredentialsProvider
                            .lookupCredentials(AmazonWebServicesCredentials.class, owner, ACL.SYSTEM,
                                    Collections.<DomainRequirement>emptyList());
            }

            return new AWSCredentialsListBoxModel()
                    .withEmptySelection()
                    .withAll(creds);
        }
    }


    public static class AWSCredentialsListBoxModel extends
            AbstractIdCredentialsListBoxModel<AWSCredentialsListBoxModel, AmazonWebServicesCredentials> {

        /**
         * {@inheritDoc}
         */
        @NonNull
        protected String describe(@NonNull AmazonWebServicesCredentials c) {
            return CredentialsNameProvider.name(c);
        }
    }
}
