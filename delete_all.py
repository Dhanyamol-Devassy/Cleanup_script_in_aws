# WARNING: This script will irreversibly delete AWS resources!
# Use only in test/dev environments with proper IAM permissions.

# Author: Dhanyamol Devassy

import boto3
import time
from botocore.exceptions import ClientError

region = "ap-south-1"

# Identity verification
def verify_identity():
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    print(f"\n>>> Using AWS Account: {identity['Account']}, ARN: {identity['Arn']}\n")

# Initialize boto3 clients
s3 = boto3.resource('s3')
s3_client = boto3.client('s3', region_name=region)
ec2 = boto3.client('ec2', region_name=region)
glue = boto3.client('glue', region_name=region)
redshift = boto3.client('redshift', region_name=region)
redshift_serverless = boto3.client('redshift-serverless', region_name=region)
iam = boto3.client('iam')
lambda_client = boto3.client('lambda', region_name=region)
rds = boto3.client('rds', region_name=region)
dynamodb = boto3.client('dynamodb', region_name=region)
sns = boto3.client('sns', region_name=region)
cloudtrail = boto3.client('cloudtrail', region_name=region)
logs = boto3.client('logs', region_name=region)
cloudwatch = boto3.client('cloudwatch', region_name=region)
events = boto3.client('events', region_name=region)

# ---------------------------
def delete_s3():
    print("\nDeleting S3 Buckets...")
    for bucket in s3.buckets.all():
        try:
            print(f"Processing bucket: {bucket.name}")
            s3_client.put_bucket_versioning(Bucket=bucket.name, VersioningConfiguration={'Status': 'Suspended'})
            bucket.object_versions.all().delete()
            bucket.objects.all().delete()
            s3_client.delete_bucket(Bucket=bucket.name)
            print(f"Deleted bucket: {bucket.name}")
        except Exception as e:
            print(f"Failed deleting {bucket.name}: {e}")

# ---------------------------
def delete_ec2():
    print("\nDeleting EC2 Instances & Related Resources...")
    try:
        reservations = ec2.describe_instances()['Reservations']
        for res in reservations:
            for instance in res['Instances']:
                instance_id = instance['InstanceId']
                print(f"Terminating instance: {instance_id}")
                ec2.terminate_instances(InstanceIds=[instance_id])
        time.sleep(10)
    except Exception as e:
        print(f"EC2 instance deletion error: {e}")

    try:
        eips = ec2.describe_addresses()['Addresses']
        for eip in eips:
            print(f"Releasing EIP: {eip['PublicIp']}")
            ec2.release_address(AllocationId=eip['AllocationId'])
    except Exception as e:
        print(f"EIP release error: {e}")

    try:
        keys = ec2.describe_key_pairs()['KeyPairs']
        for key in keys:
            print(f"Deleting Key Pair: {key['KeyName']}")
            ec2.delete_key_pair(KeyName=key['KeyName'])
    except Exception as e:
        print(f"Key pair deletion error: {e}")

    try:
        amis = ec2.describe_images(Owners=['self'])['Images']
        for ami in amis:
            print(f"Deregistering AMI: {ami['ImageId']}")
            ec2.deregister_image(ImageId=ami['ImageId'])
    except Exception as e:
        print(f"AMI deregistration error: {e}")

    try:
        snaps = ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']
        for snap in snaps:
            print(f"Deleting Snapshot: {snap['SnapshotId']}")
            ec2.delete_snapshot(SnapshotId=snap['SnapshotId'])
    except Exception as e:
        print(f"Snapshot deletion error: {e}")

    try:
        vols = ec2.describe_volumes()['Volumes']
        for vol in vols:
            print(f"Deleting Volume: {vol['VolumeId']}")
            ec2.delete_volume(VolumeId=vol['VolumeId'])
    except Exception as e:
        print(f"Volume deletion error: {e}")

    try:
        sgs = ec2.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            if sg['GroupName'] != 'default':
                print(f"Deleting Security Group: {sg['GroupId']}")
                ec2.delete_security_group(GroupId=sg['GroupId'])
    except Exception as e:
        print(f"Security group deletion error: {e}")

# ---------------------------
def delete_network_interfaces():
    print("\nDeleting ENIs...")
    try:
        enis = ec2.describe_network_interfaces()['NetworkInterfaces']
        for eni in enis:
            if eni['Status'] == 'available':
                print(f"Deleting ENI: {eni['NetworkInterfaceId']}")
                ec2.delete_network_interface(NetworkInterfaceId=eni['NetworkInterfaceId'])
    except Exception as e:
        print(f"ENI deletion error: {e}")

# ---------------------------
def delete_vpcs():
    print("\nDeleting VPCs and Associated Resources...")
    try:
        vpcs = ec2.describe_vpcs()['Vpcs']
        for vpc in vpcs:
            if vpc.get('IsDefault'): continue
            vpc_id = vpc['VpcId']
            print(f"Processing VPC: {vpc_id}")

            # Delete VPC Endpoints
            endpoints = ec2.describe_vpc_endpoints()['VpcEndpoints']
            for ep in endpoints:
                if ep['VpcId'] == vpc_id:
                    print(f"Deleting VPC Endpoint: {ep['VpcEndpointId']}")
                    ec2.delete_vpc_endpoints(VpcEndpointIds=[ep['VpcEndpointId']])

            # Delete NAT Gateway
            nat_gws = ec2.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['NatGateways']
            for nat in nat_gws:
                print(f"Deleting NAT Gateway: {nat['NatGatewayId']}")
                ec2.delete_nat_gateway(NatGatewayId=nat['NatGatewayId'])
            time.sleep(5)

            # Delete IGWs
            igws = ec2.describe_internet_gateways()['InternetGateways']
            for igw in igws:
                for attach in igw['Attachments']:
                    if attach['VpcId'] == vpc_id:
                        print(f"Detaching and Deleting IGW: {igw['InternetGatewayId']}")
                        ec2.detach_internet_gateway(InternetGatewayId=igw['InternetGatewayId'], VpcId=vpc_id)
                        ec2.delete_internet_gateway(InternetGatewayId=igw['InternetGatewayId'])

            # Delete Route Table Routes (except main route table)
            rtbs = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['RouteTables']
            for rtb in rtbs:
                rtb_id = rtb['RouteTableId']

                # First disassociate non-main associations
                for assoc in rtb['Associations']:
                    if not assoc.get('Main', False):
                        print(f"Disassociating Route Table Association: {assoc['RouteTableAssociationId']}")
                        ec2.disassociate_route_table(AssociationId=assoc['RouteTableAssociationId'])

                # Delete non-local routes (preserve local route)
                for route in rtb['Routes']:
                    if route.get('GatewayId') and route['DestinationCidrBlock'] != vpc['CidrBlock']:
                        try:
                            print(f"Deleting route {route['DestinationCidrBlock']} from RTB {rtb_id}")
                            ec2.delete_route(RouteTableId=rtb_id, DestinationCidrBlock=route['DestinationCidrBlock'])
                        except Exception as e:
                            print(f"Skipping route deletion: {e}")

            # Delete Subnets AFTER routes cleared
            subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']
            for subnet in subnets:
                print(f"Deleting Subnet: {subnet['SubnetId']}")
                ec2.delete_subnet(SubnetId=subnet['SubnetId'])

            # Finally delete Route Tables
            for rtb in rtbs:
                try:
                    print(f"Deleting Route Table: {rtb['RouteTableId']}")
                    ec2.delete_route_table(RouteTableId=rtb['RouteTableId'])
                except Exception as e:
                    print(f"Skipping RTB deletion: {e}")

            # Finally delete VPC
            print(f"Deleting VPC: {vpc_id}")
            ec2.delete_vpc(VpcId=vpc_id)

    except Exception as e:
        print(f"VPC deletion error: {e}")


# ---------------------------
def delete_glue():
    print("\nDeleting Glue Resources...")
    try:
        for crawler in glue.get_crawlers()['Crawlers']:
            print(f"Deleting Crawler: {crawler['Name']}")
            glue.delete_crawler(Name=crawler['Name'])
        for db in glue.get_databases()['DatabaseList']:
            if db['Name'] == 'default': continue
            for table in glue.get_tables(DatabaseName=db['Name'])['TableList']:
                print(f"Deleting Table: {table['Name']}")
                glue.delete_table(DatabaseName=db['Name'], Name=table['Name'])
            print(f"Deleting Database: {db['Name']}")
            glue.delete_database(Name=db['Name'])
    except Exception as e:
        print(f"Glue deletion error: {e}")

# ---------------------------
def delete_redshift_provisioned():
    print("\nDeleting Redshift Provisioned Clusters & Snapshots...")
    try:
        # Delete clusters
        clusters = redshift.describe_clusters()['Clusters']
        for cluster in clusters:
            print(f"Deleting Cluster: {cluster['ClusterIdentifier']}")
            redshift.delete_cluster(ClusterIdentifier=cluster['ClusterIdentifier'], SkipFinalClusterSnapshot=True)
        time.sleep(10)
    except Exception as e:
        print(f"Redshift cluster deletion error: {e}")

    try:
        # Delete manual snapshots
        snapshots = redshift.describe_cluster_snapshots(SnapshotType='manual')['Snapshots']
        for snap in snapshots:
            print(f"Deleting Redshift Snapshot: {snap['SnapshotIdentifier']}")
            redshift.delete_cluster_snapshot(SnapshotIdentifier=snap['SnapshotIdentifier'])
    except Exception as e:
        print(f"Redshift snapshot deletion error: {e}")

    try:
        # Delete subnet groups
        subnet_groups = redshift.describe_cluster_subnet_groups()['ClusterSubnetGroups']
        for sg in subnet_groups:
            print(f"Deleting Subnet Group: {sg['ClusterSubnetGroupName']}")
            redshift.delete_cluster_subnet_group(ClusterSubnetGroupName=sg['ClusterSubnetGroupName'])
    except Exception as e:
        print(f"Subnet group deletion error: {e}")

# ---------------------------
def delete_redshift_serverless():
    print("\nDeleting Redshift Serverless...")
    try:
        workgroups = redshift_serverless.list_workgroups()['workgroups']
        for wg in workgroups:
            print(f"Deleting Workgroup: {wg['workgroupName']}")
            redshift_serverless.delete_workgroup(workgroupName=wg['workgroupName'])
        time.sleep(15)
        namespaces = redshift_serverless.list_namespaces()['namespaces']
        for ns in namespaces:
            print(f"Deleting Namespace: {ns['namespaceName']}")
            redshift_serverless.delete_namespace(namespaceName=ns['namespaceName'])
    except Exception as e:
        print(f"Redshift serverless deletion error: {e}")

# ---------------------------
def delete_lambda():
    print("\nDeleting Lambda Functions...")
    try:
        functions = lambda_client.list_functions()['Functions']
        for func in functions:
            print(f"Deleting Lambda Function: {func['FunctionName']}")
            lambda_client.delete_function(FunctionName=func['FunctionName'])
    except Exception as e:
        print(f"Lambda deletion error: {e}")

# ---------------------------
def delete_iam_roles():
    print("\nDeleting IAM Roles...")
    try:
        roles = iam.list_roles()['Roles']
        for role in roles:
            role_name = role['RoleName']
            if role_name.startswith('AWSServiceRoleFor'): continue
            try:
                for policy in iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']:
                    iam.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
                for policy_name in iam.list_role_policies(RoleName=role_name)['PolicyNames']:
                    iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
                for profile in iam.list_instance_profiles_for_role(RoleName=role_name)['InstanceProfiles']:
                    iam.remove_role_from_instance_profile(InstanceProfileName=profile['InstanceProfileName'], RoleName=role_name)
                    iam.delete_instance_profile(InstanceProfileName=profile['InstanceProfileName'])
                print(f"Deleting IAM Role: {role_name}")
                iam.delete_role(RoleName=role_name)
            except Exception as e:
                print(f"Skipping IAM Role {role_name}: {e}")
    except Exception as e:
        print(f"IAM role deletion error: {e}")
# ---------------------------
def delete_dynamodb():
    print("\nDeleting DynamoDB Tables...")
    try:
        tables = dynamodb.list_tables()['TableNames']
        for table in tables:
            print(f"Deleting DynamoDB Table: {table}")
            dynamodb.delete_table(TableName=table)
    except Exception as e:
        print(f"DynamoDB deletion error: {e}")

# ---------------------------
def delete_rds():
    print("\nDeleting RDS Instances & Snapshots...")
    try:
        instances = rds.describe_db_instances()['DBInstances']
        for db in instances:
            print(f"Deleting RDS Instance: {db['DBInstanceIdentifier']}")
            rds.delete_db_instance(DBInstanceIdentifier=db['DBInstanceIdentifier'], SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
        time.sleep(10)
    except Exception as e:
        print(f"RDS instance deletion error: {e}")

    try:
        snapshots = rds.describe_db_snapshots(SnapshotType='manual')['DBSnapshots']
        for snap in snapshots:
            print(f"Deleting RDS Snapshot: {snap['DBSnapshotIdentifier']}")
            rds.delete_db_snapshot(DBSnapshotIdentifier=snap['DBSnapshotIdentifier'])
    except Exception as e:
        print(f"RDS snapshot deletion error: {e}")

# ---------------------------
def delete_sns():
    print("\nDeleting SNS Topics...")
    try:
        topics = sns.list_topics()['Topics']
        for topic in topics:
            print(f"Deleting SNS Topic: {topic['TopicArn']}")
            sns.delete_topic(TopicArn=topic['TopicArn'])
    except Exception as e:
        print(f"SNS deletion error: {e}")

# ---------------------------
def delete_cloudtrail():
    print("\nDeleting CloudTrail...")
    try:
        trails = cloudtrail.describe_trails()['trailList']
        for trail in trails:
            print(f"Deleting CloudTrail Trail: {trail['Name']}")
            cloudtrail.delete_trail(Name=trail['Name'])
    except Exception as e:
        print(f"CloudTrail deletion error: {e}")

# ---------------------------
def delete_cloudwatch():
    print("\nDeleting CloudWatch Logs & Alarms...")
    try:
        log_groups = logs.describe_log_groups()['logGroups']
        for log_group in log_groups:
            print(f"Deleting Log Group: {log_group['logGroupName']}")
            logs.delete_log_group(logGroupName=log_group['logGroupName'])
    except Exception as e:
        print(f"CloudWatch log group deletion error: {e}")

    try:
        alarms = cloudwatch.describe_alarms()['MetricAlarms']
        for alarm in alarms:
            print(f"Deleting Alarm: {alarm['AlarmName']}")
            cloudwatch.delete_alarms(AlarmNames=[alarm['AlarmName']])
    except Exception as e:
        print(f"CloudWatch alarm deletion error: {e}")

# ---------------------------
def delete_eventbridge():
    print("\nDeleting EventBridge Rules...")
    try:
        rules = events.list_rules()['Rules']
        for rule in rules:
            targets = events.list_targets_by_rule(Rule=rule['Name'])['Targets']
            if targets:
                events.remove_targets(Rule=rule['Name'], Ids=[t['Id'] for t in targets])
            print(f"Deleting EventBridge Rule: {rule['Name']}")
            events.delete_rule(Name=rule['Name'])
    except Exception as e:
        print(f"EventBridge deletion error: {e}")

# ---------------------------
# CLEANUP RUNNER
# ---------------------------
if __name__ == "__main__":
    verify_identity()
    delete_s3()
    delete_ec2()
    delete_network_interfaces()
    delete_vpcs()
    delete_glue()
    delete_redshift_provisioned()
    delete_redshift_serverless()
    delete_lambda()
    delete_iam_roles()
    delete_dynamodb()
    delete_rds()
    delete_sns()
    delete_cloudtrail()
    delete_cloudwatch()
    delete_eventbridge()
    print("\nFULL AWS CLEANUP COMPLETED")
