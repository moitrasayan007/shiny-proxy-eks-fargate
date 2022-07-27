# shiny-proxy-eks-fargate

### [AWS CodeStar Connections](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarconnections-connection.html):

- To manage access to GitHub Repository (so we do not need to use a private access token).

We need to create a codestar connection from AWS account. This will be used as a source which will create the EKS Fargate cluster and also deploy sample shiny app to EKS fargate.

Once the connection is established between your AWS account and github, please proceed to next step.

Upload the `cloudformation-codepipeline.yml` in the stack.

It will ask for the below parameters - 

1. SourceConnectionArn - The ARN of the connection to the external source code repository.

2. RepositoryOwner - The owner of the GitHub repository.

3. RepositoryName - The name of the GitHub repository.

4. RepositoryBranch - The name of the branch.

5. KubeProxyECR - The name of the Kube Proxy ECR.

6. ShinyProxyECR - The name of the Shiny Proxy ECR.

7. ShinyAppECR - The name of the Shiny App ECR.

8. EksStackName - The name of the EKS Cloudformation Stack.

This will create an EKS cluster with fargate profile, and also deploy sample shiny app in EKS.