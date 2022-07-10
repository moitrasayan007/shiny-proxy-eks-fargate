"""
Purpose

Example of how to provision an EKS cluster, create the IAM Roles for Service Accounts (IRSA) mappings,
and then deploy various common cluster add-ons (AWS Load Balancer Controller, ExternalDNS, EBS & EFS CSI Drivers,
Cluster Autoscaler, AWS Managed OpenSearch and fluentbit, Metrics Server, Calico Network Policy provider,
CloudWatch Container Insights, Security Groups for Pods, Kubecost, AWS Managed Prometheus and Grafana, etc.)

NOTE: This pulls many parameters/options for what you'd like from the cdk.json context section.
Have a look there for many options you can change to customise this template for your environments/needs.
"""

from constructs import Construct
from aws_cdk import App, Stack, Environment, CfnOutput, RemovalPolicy
from aws_cdk import (
    aws_ec2 as ec2,
    aws_eks as eks,
    aws_iam as iam,
    aws_opensearchservice as opensearch,
    aws_logs as logs,
    aws_certificatemanager as cm,
    aws_efs as efs,
    aws_aps as aps
)
import os
import yaml


class EKSClusterStack(Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Either create a new IAM role to administrate the cluster or create a new one
        if (self.node.try_get_context("create_new_cluster_admin_role") == "True"):
            cluster_admin_role = iam.Role(self, "ClusterAdminRole",
                                          assumed_by=iam.CompositePrincipal(
                                              iam.AccountRootPrincipal(),
                                              iam.ServicePrincipal(
                                                  "ec2.amazonaws.com")
                                          )
                                          )
            cluster_admin_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "eks:DescribeCluster"
                ],
                "Resource": "*"
            }
            cluster_admin_role.add_to_principal_policy(
                iam.PolicyStatement.from_json(cluster_admin_policy_statement_json_1))
        else:
            # You'll also need to add a trust relationship to ec2.amazonaws.com to sts:AssumeRole to this as well
            cluster_admin_role = iam.Role.from_role_arn(self, "ClusterAdminRole",
                                                        role_arn=self.node.try_get_context(
                                                            "existing_admin_role_arn")
                                                        )

        # Either create a new VPC with the options below OR import an existing one by name
        if (self.node.try_get_context("create_new_vpc") == "True"):
            eks_vpc = ec2.Vpc(
                self, "VPC",
                # We are choosing to spread our VPC across 3 availability zones
                max_azs=3,
                cidr=self.node.try_get_context("vpc_cidr"),
                subnet_configuration=[
                    # 3 x Public Subnets (1 per AZ) with 64 IPs each for our ALBs and NATs
                    ec2.SubnetConfiguration(
                        subnet_type=ec2.SubnetType.PUBLIC,
                        name="Public",
                        cidr_mask=self.node.try_get_context(
                            "vpc_cidr_mask_public")
                    ),
                    # 3 x Private Subnets (1 per AZ) with 256 IPs each for our Nodes and Pods
                    ec2.SubnetConfiguration(
                        subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT,
                        name="Private",
                        cidr_mask=self.node.try_get_context(
                            "vpc_cidr_mask_private")
                    )
                ]
            )
        else:
            eks_vpc = ec2.Vpc.from_lookup(
                self, 'VPC', vpc_name=self.node.try_get_context("existing_vpc_name"))

        # Create an EKS Cluster
        eks_cluster = eks.Cluster(
            self, "cluster",
            vpc=eks_vpc,
            masters_role=cluster_admin_role,
            # Make our cluster's control plane accessible only within our private VPC
            # This means that we'll have to ssh to a jumpbox/bastion or set up a VPN to manage it
            endpoint_access=eks.EndpointAccess.PRIVATE,
            version=eks.KubernetesVersion.of(
                self.node.try_get_context("eks_version")),
            default_capacity=0,
            cluster_logging=[eks.ClusterLoggingTypes.API, eks.ClusterLoggingTypes.AUDIT,
                             eks.ClusterLoggingTypes.AUTHENTICATOR, eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
                             eks.ClusterLoggingTypes.SCHEDULER]
        )

        # Create a Fargate Pod Execution Role to use with any Fargate Profiles
        # We create this explicitly to allow for logging without fargate_only_cluster=True
        fargate_pod_execution_role = iam.Role(
            self, "FargatePodExecutionRole",
            assumed_by=iam.ServicePrincipal("eks-fargate-pods.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "AmazonEKSFargatePodExecutionRolePolicy")]
        )

        # Create the CF exports that let you rehydrate the Cluster object in other stack(s)
        if (self.node.try_get_context("create_cluster_exports") == "True"):
            # Output the EKS Cluster Name and Export it
            CfnOutput(
                self, "EKSClusterName",
                value=eks_cluster.cluster_name,
                description="The name of the EKS Cluster",
                export_name="EKSClusterName"
            )
            # Output the EKS Cluster OIDC Issuer and Export it
            CfnOutput(
                self, "EKSClusterOIDCProviderARN",
                value=eks_cluster.open_id_connect_provider.open_id_connect_provider_arn,
                description="The EKS Cluster's OIDC Provider ARN",
                export_name="EKSClusterOIDCProviderARN"
            )
            # Output the EKS Cluster kubectl Role ARN
            CfnOutput(
                self, "EKSClusterKubectlRoleARN",
                value=eks_cluster.kubectl_role.role_arn,
                description="The EKS Cluster's kubectl Role ARN",
                export_name="EKSClusterKubectlRoleARN"
            )
            # Output the EKS Cluster SG ID
            CfnOutput(
                self, "EKSSGID",
                value=eks_cluster.kubectl_security_group.security_group_id,
                description="The EKS Cluster's kubectl SG ID",
                export_name="EKSSGID"
            )
            # Output the EKS Fargate Pod Execution Role (to use for logging to work)
            CfnOutput(
                self, "EKSFargatePodExecRoleArn",
                value=fargate_pod_execution_role.role_arn,
                description="The EKS Cluster's Fargate Pod Execution Role ARN",
                export_name="EKSFargatePodExecRoleArn"
            )

        # AWS Load Balancer Controller
        if (self.node.try_get_context("deploy_aws_lb_controller") == "True"):
            awslbcontroller_service_account = eks_cluster.add_service_account(
                "aws-load-balancer-controller",
                name="aws-load-balancer-controller",
                namespace="kube-system"
            )

            # Create the PolicyStatements to attach to the role
            # Got the required policy from https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/main/docs/install/iam_policy.json
            awslbcontroller_policy_document_json = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:CreateServiceLinkedRole",
                            "ec2:DescribeAccountAttributes",
                            "ec2:DescribeAddresses",
                            "ec2:DescribeAvailabilityZones",
                            "ec2:DescribeInternetGateways",
                            "ec2:DescribeVpcs",
                            "ec2:DescribeSubnets",
                            "ec2:DescribeSecurityGroups",
                            "ec2:DescribeInstances",
                            "ec2:DescribeNetworkInterfaces",
                            "ec2:DescribeTags",
                            "ec2:GetCoipPoolUsage",
                            "ec2:DescribeCoipPools",
                            "elasticloadbalancing:DescribeLoadBalancers",
                            "elasticloadbalancing:DescribeLoadBalancerAttributes",
                            "elasticloadbalancing:DescribeListeners",
                            "elasticloadbalancing:DescribeListenerCertificates",
                            "elasticloadbalancing:DescribeSSLPolicies",
                            "elasticloadbalancing:DescribeRules",
                            "elasticloadbalancing:DescribeTargetGroups",
                            "elasticloadbalancing:DescribeTargetGroupAttributes",
                            "elasticloadbalancing:DescribeTargetHealth",
                            "elasticloadbalancing:DescribeTags"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "cognito-idp:DescribeUserPoolClient",
                            "acm:ListCertificates",
                            "acm:DescribeCertificate",
                            "iam:ListServerCertificates",
                            "iam:GetServerCertificate",
                            "waf-regional:GetWebACL",
                            "waf-regional:GetWebACLForResource",
                            "waf-regional:AssociateWebACL",
                            "waf-regional:DisassociateWebACL",
                            "wafv2:GetWebACL",
                            "wafv2:GetWebACLForResource",
                            "wafv2:AssociateWebACL",
                            "wafv2:DisassociateWebACL",
                            "shield:GetSubscriptionState",
                            "shield:DescribeProtection",
                            "shield:CreateProtection",
                            "shield:DeleteProtection"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:AuthorizeSecurityGroupIngress",
                            "ec2:RevokeSecurityGroupIngress"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateSecurityGroup"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateTags"
                        ],
                        "Resource": "arn:aws:ec2:*:*:security-group/*",
                        "Condition": {
                            "StringEquals": {
                                "ec2:CreateAction": "CreateSecurityGroup"
                            },
                            "Null": {
                                "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateTags",
                            "ec2:DeleteTags"
                        ],
                        "Resource": "arn:aws:ec2:*:*:security-group/*",
                        "Condition": {
                            "Null": {
                                "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                                "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:AuthorizeSecurityGroupIngress",
                            "ec2:RevokeSecurityGroupIngress",
                            "ec2:DeleteSecurityGroup"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "Null": {
                                "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:CreateLoadBalancer",
                            "elasticloadbalancing:CreateTargetGroup"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "Null": {
                                "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:CreateListener",
                            "elasticloadbalancing:DeleteListener",
                            "elasticloadbalancing:CreateRule",
                            "elasticloadbalancing:DeleteRule"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:AddTags",
                            "elasticloadbalancing:RemoveTags"
                        ],
                        "Resource": [
                            "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                            "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                            "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
                        ],
                        "Condition": {
                            "Null": {
                                "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                                "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:AddTags",
                            "elasticloadbalancing:RemoveTags"
                        ],
                        "Resource": [
                            "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
                            "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
                            "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
                            "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
                        ]
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:ModifyLoadBalancerAttributes",
                            "elasticloadbalancing:SetIpAddressType",
                            "elasticloadbalancing:SetSecurityGroups",
                            "elasticloadbalancing:SetSubnets",
                            "elasticloadbalancing:DeleteLoadBalancer",
                            "elasticloadbalancing:ModifyTargetGroup",
                            "elasticloadbalancing:ModifyTargetGroupAttributes",
                            "elasticloadbalancing:DeleteTargetGroup"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "Null": {
                                "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:RegisterTargets",
                            "elasticloadbalancing:DeregisterTargets"
                        ],
                        "Resource": "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:SetWebAcl",
                            "elasticloadbalancing:ModifyListener",
                            "elasticloadbalancing:AddListenerCertificates",
                            "elasticloadbalancing:RemoveListenerCertificates",
                            "elasticloadbalancing:ModifyRule"
                        ],
                        "Resource": "*"
                    }
                ]
            }

            # Attach the necessary permissions
            awslbcontroller_policy = iam.Policy(
                self, "awslbcontrollerpolicy",
                document=iam.PolicyDocument.from_json(
                    awslbcontroller_policy_document_json)
            )
            awslbcontroller_service_account.role.attach_inline_policy(
                awslbcontroller_policy)

            # Deploy the AWS Load Balancer Controller from the AWS Helm Chart
            # For more info check out https://github.com/aws/eks-charts/tree/master/stable/aws-load-balancer-controller
            awslbcontroller_chart = eks_cluster.add_helm_chart(
                "aws-load-balancer-controller",
                chart="aws-load-balancer-controller",
                version="1.4.2",
                release="awslbcontroller",
                repository="https://aws.github.io/eks-charts",
                namespace="kube-system",
                values={
                    "clusterName": eks_cluster.cluster_name,
                    "region": self.region,
                    "vpcId": eks_vpc.vpc_id,
                    "serviceAccount": {
                        "create": False,
                        "name": "aws-load-balancer-controller"
                    },
                    "replicaCount": 2,
                    "podDisruptionBudget": {
                        "maxUnavailable": 1
                    },
                    "resources": {
                        "requests": {
                            "cpu": "0.25",
                            "memory": "0.5Gi"
                        }
                    }
                }
            )
            awslbcontroller_chart.node.add_dependency(
                awslbcontroller_service_account)

        # Metrics Server (required for the Horizontal Pod Autoscaler (HPA))
        if (self.node.try_get_context("deploy_metrics_server") == "True"):
            # For more info see https://github.com/kubernetes-sigs/metrics-server/tree/master/charts/metrics-server
            # Changed from the Bitnami chart for Graviton/ARM64 support
            metricsserver_chart = eks_cluster.add_helm_chart(
                "metrics-server",
                chart="metrics-server",
                version="3.7.0",
                release="metricsserver",
                repository="https://kubernetes-sigs.github.io/metrics-server/",
                namespace="kube-system",
                values={
                    "resources": {
                        "requests": {
                            "cpu": "0.25",
                            "memory": "0.5Gi"
                        }
                    }
                }
            )

        # Bastion Instance
        if (self.node.try_get_context("deploy_bastion") == "True"):
            # If we created a new IAM role for Admin add the rights for SSM to manage the Instance to it
            # since we're also assigning it to this instance and want to use Session Manager
            if (self.node.try_get_context("create_new_cluster_admin_role") == "True"):
                cluster_admin_role.add_managed_policy(
                    iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))

            # Create Bastion
            # Get Latest Amazon Linux AMI
            amzn_linux = ec2.MachineImage.latest_amazon_linux(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
                edition=ec2.AmazonLinuxEdition.STANDARD,
                virtualization=ec2.AmazonLinuxVirt.HVM,
                storage=ec2.AmazonLinuxStorage.GENERAL_PURPOSE
            )

            # Create SecurityGroup for bastion
            bastion_security_group = ec2.SecurityGroup(
                self, "BastionSecurityGroup",
                vpc=eks_vpc,
                allow_all_outbound=True
            )

            # Add a rule to allow our new SG to talk to the EKS control plane
            eks_cluster.cluster_security_group.add_ingress_rule(
                bastion_security_group,
                ec2.Port.all_traffic()
            )

            # Create our EC2 instance for bastion
            bastion_instance = ec2.Instance(
                self, "BastionInstance",
                instance_type=ec2.InstanceType(
                    self.node.try_get_context("bastion_node_type")),
                machine_image=amzn_linux,
                role=cluster_admin_role,
                vpc=eks_vpc,
                vpc_subnets=ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.PUBLIC),
                security_group=bastion_security_group,
                block_devices=[ec2.BlockDevice(
                    device_name="/dev/xvda", volume=ec2.BlockDeviceVolume.ebs(self.node.try_get_context("bastion_disk_size")))]
            )

            # Set up our kubectl and fluxctl
            bastion_instance.user_data.add_commands(
                "curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.21.2/2021-07-05/bin/linux/amd64/kubectl")
            bastion_instance.user_data.add_commands("chmod +x ./kubectl")
            bastion_instance.user_data.add_commands("mv ./kubectl /usr/bin")
            bastion_instance.user_data.add_commands(
                "curl -s https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash -")
            bastion_instance.user_data.add_commands(
                "curl -s https://fluxcd.io/install.sh | bash -")
            bastion_instance.user_data.add_commands(
                "curl --silent --location https://rpm.nodesource.com/setup_14.x | bash -")
            bastion_instance.user_data.add_commands(
                "yum install nodejs git -y")
            bastion_instance.user_data.add_commands(
                "su -c \"aws eks update-kubeconfig --name " + eks_cluster.cluster_name + " --region " + self.region + "\" ssm-user")

            # Wait to deploy Bastion until cluster is up and we're deploying manifests/charts to it
            # This could be any of the charts/manifests I just picked this one as almost everybody will want it
            bastion_instance.node.add_dependency(metricsserver_chart)

        # CloudWatch Container Insights - Metrics
        if (self.node.try_get_context("deploy_cloudwatch_container_insights_metrics") == "True"):
            # For more info see https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-metrics.html

            # Create the Service Account
            cw_container_insights_sa = eks_cluster.add_service_account(
                "cloudwatch-agent",
                name="cloudwatch-agent",
                namespace="kube-system"
            )
            cw_container_insights_sa.role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchAgentServerPolicy"))

            # Set up the settings ConfigMap
            cw_container_insights_configmap = eks_cluster.add_manifest("CWAgentConfigMap", {
                "apiVersion": "v1",
                "data": {
                    "cwagentconfig.json": "{\n  \"logs\": {\n    \"metrics_collected\": {\n      \"kubernetes\": {\n        \"cluster_name\": \"" + eks_cluster.cluster_name + "\",\n        \"metrics_collection_interval\": 60\n      }\n    },\n    \"force_flush_interval\": 5\n  }\n}\n"
                },
                "kind": "ConfigMap",
                "metadata": {
                    "name": "cwagentconfig",
                    "namespace": "kube-system"
                }
            })

            # Import cloudwatch-agent.yaml to a list of dictionaries and submit them as a manifest to EKS
            # Read the YAML file
            cw_agent_yaml_file = open("cloudwatch-agent.yaml", 'r')
            cw_agent_yaml = list(yaml.load_all(
                cw_agent_yaml_file, Loader=yaml.FullLoader))
            cw_agent_yaml_file.close()
            loop_iteration = 0
            for value in cw_agent_yaml:
                # print(value)
                loop_iteration = loop_iteration + 1
                manifest_id = "CWAgent" + str(loop_iteration)
                eks_cluster.add_manifest(manifest_id, value)

        # CloudWatch Container Insights - Logs
        if (self.node.try_get_context("deploy_cloudwatch_container_insights_logs") == "True"):
            # Create the Service Account
            fluentbit_cw_service_account = eks_cluster.add_service_account(
                "fluentbit-cw",
                name="fluentbit-cw",
                namespace="kube-system"
            )

            fluentbit_cw_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "logs:PutLogEvents",
                    "logs:DescribeLogStreams",
                    "logs:DescribeLogGroups",
                    "logs:CreateLogStream",
                    "logs:CreateLogGroup",
                    "logs:PutRetentionPolicy"
                ],
                "Resource": ["*"]
            }

            # Add the policies to the service account
            fluentbit_cw_service_account.add_to_principal_policy(
                iam.PolicyStatement.from_json(fluentbit_cw_policy_statement_json_1))

            # For more info check out https://github.com/fluent/helm-charts/tree/main/charts/fluent-bit
            # Matched the config suggsted for Fargate for consistency https://docs.aws.amazon.com/eks/latest/userguide/fargate-logging.html
            fluentbit_chart_cw = eks_cluster.add_helm_chart(
                "fluentbit-cw",
                chart="fluent-bit",
                version="0.19.17",
                release="fluent-bit-cw",
                repository="https://fluent.github.io/helm-charts",
                namespace="kube-system",
                values={
                    "serviceAccount": {
                        "create": False,
                        "name": "fluentbit-cw"
                    },
                    "config": {
                        "outputs": "[OUTPUT]\n    Name cloudwatch_logs\n    Match   *\n    region " + self.region + "\n    log_group_name fluent-bit-cloudwatch\n    log_stream_prefix from-fluent-bit-\n    auto_create_group true\n    log_retention_days " + str(self.node.try_get_context("cloudwatch_container_insights_logs_retention_days")) + "\n",
                        "filters.conf": "[FILTER]\n  Name  kubernetes\n  Match  kube.*\n  Merge_Log  On\n  Buffer_Size  0\n  Kube_Meta_Cache_TTL  300s"
                    }
                }
            )
            fluentbit_chart_cw.node.add_dependency(
                fluentbit_cw_service_account)

        # Security Group for Pods
        if (self.node.try_get_context("deploy_sg_for_pods") == "True"):
            # The EKS Cluster was still defaulting to 1.7.5 on 12/9/21 and SG for Pods requires 1.7.7
            # Upgrading that to the latest version 1.9.0 via the Helm Chart
            # If this process somehow breaks the CNI you can repair it manually by following the steps here:
            # https://docs.aws.amazon.com/eks/latest/userguide/managing-vpc-cni.html#updating-vpc-cni-add-on
            # TODO: Move this to the CNI Managed Add-on when that supports flipping the required ENABLE_POD_ENI setting

            # Adopting the existing aws-node resources to Helm
            patch_types = ["DaemonSet", "ClusterRole", "ClusterRoleBinding"]
            patches = []
            for kind in patch_types:
                patch = eks.KubernetesPatch(
                    self, "CNI-Patch-"+kind,
                    cluster=eks_cluster,
                    resource_name=kind + "/aws-node",
                    resource_namespace="kube-system",
                    apply_patch={
                        "metadata": {
                            "annotations": {
                                "meta.helm.sh/release-name": "aws-vpc-cni",
                                "meta.helm.sh/release-namespace": "kube-system",
                            },
                            "labels": {
                                "app.kubernetes.io/managed-by": "Helm"
                            }
                        }
                    },
                    restore_patch={},
                    patch_type=eks.PatchType.STRATEGIC
                )
                # We don't want to clean this up on Delete - it is a one-time patch to let the Helm Chart own the resources
                patch_resource = patch.node.find_child("Resource")
                patch_resource.apply_removal_policy(RemovalPolicy.RETAIN)
                # Keep track of all the patches to set dependencies down below
                patches.append(patch)

            # Create the Service Account
            sg_pods_service_account = eks_cluster.add_service_account(
                "aws-node",
                name="aws-node-helm",
                namespace="kube-system"
            )

            # Give it the required policies
            sg_pods_service_account.role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKS_CNI_Policy"))
            # sg_pods_service_account.role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSVPCResourceController"))
            eks_cluster.role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSVPCResourceController"))

            # Deploy the Helm chart
            # For more info check out https://github.com/aws/eks-charts/tree/master/stable/aws-vpc-cni
            # Note that for some regions different account # required - https://docs.aws.amazon.com/eks/latest/userguide/add-ons-images.html
            sg_pods_chart = eks_cluster.add_helm_chart(
                "aws-vpc-cni",
                chart="aws-vpc-cni",
                version="1.1.12",
                release="aws-vpc-cni",
                repository="https://aws.github.io/eks-charts",
                namespace="kube-system",
                values={
                    "init": {
                        "image": {
                            "region": self.region,
                            "account": "602401143452",
                        },
                        "env": {
                            "DISABLE_TCP_EARLY_DEMUX": True
                        }
                    },
                    "image": {
                        "region": self.region,
                        "account": "602401143452"
                    },
                    "env": {
                        "ENABLE_POD_ENI": True
                    },
                    "serviceAccount": {
                        "create": False,
                        "name": "aws-node-helm"
                    },
                    "crd": {
                        "create": False
                    },
                    "originalMatchLabels": True
                }
            )
            # This depends both on the service account and the patches to the existing CNI resources having been done first
            sg_pods_chart.node.add_dependency(sg_pods_service_account)
            for patch in patches:
                sg_pods_chart.node.add_dependency(patch)

        # Run everything via Fargate (i.e. no EC2 Nodes/Managed Node Group)
        # NOTE: You need to add any namespaces other than kube-system and default to this
        # OR create additional Fargate Profiles with the additional namespaces/labels
        if (self.node.try_get_context("fargate_only_cluster") == "True"):
            # Remove the annotation on CoreDNS forcing it onto EC2 (so it can run on Fargate)
            coredns_fargate_patch = eks.KubernetesPatch(
                self, "CoreDNSFargatePatch",
                cluster=eks_cluster,
                resource_name="deployment/coredns",
                resource_namespace="kube-system",
                apply_patch={
                    "spec": {
                        "template": {
                            "metadata": {
                                "annotations": {
                                    "eks.amazonaws.com/compute-type": "fargate"
                                }
                            }
                        }
                    }
                },
                restore_patch={
                    "spec": {
                        "template": {
                            "metadata": {
                                "annotations": {
                                    "eks.amazonaws.com/compute-type": "ec2"
                                }
                            }
                        }
                    }
                },
                patch_type=eks.PatchType.STRATEGIC
            )

            # Set up a Fargate profile covering both the kube-system and default namespaces
            default_fargate_profile = eks_cluster.add_fargate_profile(
                "DefaultFargateProfile",
                fargate_profile_name="default",
                pod_execution_role=fargate_pod_execution_role,
                selectors=[eks.Selector(
                    namespace="kube-system",), eks.Selector(namespace="default"), eks.Selector(namespace="shinyproxy")]
            )

        # Send Fargate logs to CloudWatch Logs
        if (self.node.try_get_context("fargate_logs_to_cloudwatch") == "True"):
            # See https://docs.aws.amazon.com/eks/latest/userguide/fargate-logging.html

            # Add the relevant IAM policy to the Fargate Pod Execution Role
            fargate_cw_logs_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "logs:PutLogEvents",
                    "logs:DescribeLogStreams",
                    "logs:DescribeLogGroups",
                    "logs:CreateLogStream",
                    "logs:CreateLogGroup",
                    "logs:PutRetentionPolicy"
                ],
                "Resource": "*"
            }
            fargate_pod_execution_role.add_to_principal_policy(
                iam.PolicyStatement.from_json(fargate_cw_logs_policy_statement_json_1))

            fargate_namespace_manifest = eks_cluster.add_manifest("FargateLoggingNamespace", {
                "kind": "Namespace",
                "apiVersion": "v1",
                "metadata": {
                    "name": "aws-observability",
                    "labels": {
                        "aws-observability": "enabled"
                    }
                }
            })

            fargate_fluentbit_manifest_cw = eks_cluster.add_manifest("FargateLoggingCW", {
                "kind": "ConfigMap",
                "apiVersion": "v1",
                "metadata": {
                    "name": "aws-logging",
                    "namespace": "aws-observability"
                },
                "data": {
                    "output.conf": "[OUTPUT]\n    Name cloudwatch_logs\n    Match   *\n    region " + self.region + "\n    log_group_name fluent-bit-cloudwatch\n    log_stream_prefix from-fluent-bit-\n    auto_create_group true\n    log_retention_days " + str(self.node.try_get_context("cloudwatch_container_insights_logs_retention_days")) + "\n",
                    "filters.conf": "[FILTER]\n  Name  kubernetes\n  Match  kube.*\n  Merge_Log  On\n  Buffer_Size  0\n  Kube_Meta_Cache_TTL  300s"
                }
            })
            fargate_fluentbit_manifest_cw.node.add_dependency(
                fargate_namespace_manifest)
        else:
            print("You need to set only one destination for Fargate Logs to True")

        # Send Fargate logs to the managed OpenSearch
        # NOTE This is of limited usefulness without the Kubernetes filter to enrich it with k8s metadata
        # This is on the roadmap see https://github.com/aws/containers-roadmap/issues/1197
        # At the moment better to use CloudWatch logs which seperates by source logstream and onward
        # stream from that to OpenSearch?


app = App()
if app.node.try_get_context("account").strip() != "":
    account = app.node.try_get_context("account")
else:
    account = os.environ.get("CDK_DEPLOY_ACCOUNT",
                             os.environ["CDK_DEFAULT_ACCOUNT"])

if app.node.try_get_context("region").strip() != "":
    region = app.node.try_get_context("region")
else:
    region = os.environ.get("CDK_DEPLOY_REGION",
                            os.environ["CDK_DEFAULT_REGION"])
# Note that if we didn't pass through the ACCOUNT and REGION from these environment variables that
# it won't let us create 3 AZs and will only create a max of 2 - even when we ask for 3 in eks_vpc
eks_cluster_stack = EKSClusterStack(
    app, "EKSClusterStack", env=Environment(account=account, region=region))
app.synth()
