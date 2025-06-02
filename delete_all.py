# WARNING: This script will irreversibly delete AWS resources!
# Use only in test/dev environments with proper IAM permissions.

#Author: Dhanyamol Devassy

import boto3
import time

region = "ap-south-1"

# AWS Clients
s3 = boto3.resource('s3')
s3_client = boto3.client('s3')
sns = boto3.client('sns')
iam = boto3.client('iam')
ec2 = boto3.client("ec2", region_name=region)
rds = boto3.client("rds", region_name=region)
lambda_client = boto3.client("lambda", region_name=region)
dynamodb = boto3.client("dynamodb", region_name=region)
cloudtrail = boto3.client("cloudtrail", region_name=region)
logs = boto3.client("logs", region_name=region)
cloudwatch = boto3.client("cloudwatch", region_name=region)
cloudwatch_events = boto3.client("events", region_name=region)

# ---------- S3 ----------
def delete_all_s3_buckets():
    print("Deleting all S3 buckets and objects...")
    for bucket in s3.buckets.all():
        print(f"Emptying and deleting bucket: {bucket.name}")
        try:
            s3_client.put_bucket_versioning(Bucket=bucket.name, VersioningConfiguration={'Status': 'Suspended'})
            bucket.object_versions.all().delete()
            bucket.objects.all().delete()
        except: pass
        try:
            s3_client.delete_bucket(Bucket=bucket.name)
            print(f"Deleted bucket: {bucket.name}")
        except Exception as e:
            print(f"Error deleting bucket {bucket.name}: {e}")

# ---------- SNS ----------
def delete_all_sns_topics():
    print("Deleting SNS topics and subscriptions...")
    topics = sns.list_topics().get('Topics', [])
    for topic in topics:
        arn = topic['TopicArn']
        try:
            subscriptions = sns.list_subscriptions_by_topic(TopicArn=arn).get("Subscriptions", [])
            for sub in subscriptions:
                if sub["SubscriptionArn"] != "PendingConfirmation":
                    sns.unsubscribe(SubscriptionArn=sub["SubscriptionArn"])
            sns.delete_topic(TopicArn=arn)
            print(f"Deleted topic and subscriptions: {arn}")
        except Exception as e:
            print(f"Error deleting topic {arn}: {e}")

# ---------- IAM ----------
def delete_all_iam_users_roles_groups():
    print("Deleting IAM users, roles, and groups...")
    for user in iam.list_users()["Users"]:
        name = user["UserName"]
        print(f"Deleting user: {name}")
        try:
            iam.delete_login_profile(UserName=name)
        except: pass
        try:
            for policy in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]:
                iam.detach_user_policy(UserName=name, PolicyArn=policy["PolicyArn"])
            iam.delete_user(UserName=name)
        except Exception as e:
            print(f"Error deleting user {name}: {e}")

    for role in iam.list_roles()["Roles"]:
        name = role["RoleName"]
        if name.startswith("AWSServiceRoleFor"):
            continue

        print(f"Cleaning up role: {name}")

        # Detach managed policies
        try:
            for policy in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=name, PolicyArn=policy["PolicyArn"])
                print(f"Detached managed policy from role: {name}")
        except Exception as e:
            print(f"Error detaching policies from role {name}: {e}")

       # Delete inline policies
        try:
            inline_policies = iam.list_role_policies(RoleName=name)["PolicyNames"]
            for policy_name in inline_policies:
                iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
                print(f"Deleted inline policy '{policy_name}' from role: {name}")
        except Exception as e:
            print(f"Error deleting inline policies for role {name}: {e}")

        # Remove from instance profiles
        try:
            instance_profiles = iam.list_instance_profiles_for_role(RoleName=name)["InstanceProfiles"]
            for profile in instance_profiles:
                iam.remove_role_from_instance_profile(
                    InstanceProfileName=profile["InstanceProfileName"],
                    RoleName=name
                )
                print(f"Removed role {name} from instance profile {profile['InstanceProfileName']}")
                iam.delete_instance_profile(InstanceProfileName=profile["InstanceProfileName"])
                print(f"Deleted instance profile: {profile['InstanceProfileName']}")
        except Exception as e:
            print(f"Error removing role {name} from instance profiles: {e}")

       # Delete the role
        try:
            iam.delete_role(RoleName=name)
            print(f"Deleted role: {name}")
        except Exception as e:
            print(f"Error deleting role {name}: {e}")
   

    for group in iam.list_groups()["Groups"]:
        name = group["GroupName"]
        print(f"Deleting group: {name}")
        try:
            for user in iam.get_group(GroupName=name)["Users"]:
                iam.remove_user_from_group(GroupName=name, UserName=user["UserName"])
            for policy in iam.list_attached_group_policies(GroupName=name)["AttachedPolicies"]:
                iam.detach_group_policy(GroupName=name, PolicyArn=policy["PolicyArn"])
            iam.delete_group(GroupName=name)
        except Exception as e:
            print(f"Error deleting group {name}: {e}")

# ---------- EC2 ----------
def delete_ec2_resources():
    print("Terminating EC2 instances...")
    instances = ec2.describe_instances()
    for reservation in instances["Reservations"]:
        for instance in reservation["Instances"]:
            instance_id = instance["InstanceId"]
            ec2.terminate_instances(InstanceIds=[instance_id])
            print(f"Terminated instance: {instance_id}")
    time.sleep(10)

    print("Releasing Elastic IPs...")
    for eip in ec2.describe_addresses()["Addresses"]:
        try:
            ec2.release_address(AllocationId=eip["AllocationId"])
            print(f"Released Elastic IP: {eip['PublicIp']}")
        except Exception as e:
            print(f"Could not release EIP {eip['PublicIp']}: {e}")

    print("Deleting key pairs...")
    for key in ec2.describe_key_pairs()["KeyPairs"]:
        ec2.delete_key_pair(KeyName=key["KeyName"])
        print(f"Deleted key pair: {key['KeyName']}")

    print("Deleting non-default security groups...")
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        if sg["GroupName"] != "default":
            try:
                ec2.delete_security_group(GroupId=sg["GroupId"])
                print(f"Deleted security group: {sg['GroupId']}")
            except Exception as e:
                print(f"Could not delete security group {sg['GroupId']}: {e}")

    print("Deleting EBS volumes...")
    for vol in ec2.describe_volumes()["Volumes"]:
        try:
            ec2.delete_volume(VolumeId=vol["VolumeId"])
            print(f"Deleted volume: {vol['VolumeId']}")
        except Exception as e:
            print(f"Could not delete volume {vol['VolumeId']}: {e}")

    print("Deregistering owned AMIs...")
    for image in ec2.describe_images(Owners=["self"])["Images"]:
        ec2.deregister_image(ImageId=image["ImageId"])
        print(f"Deregistered AMI: {image['ImageId']}")

# ---------- Lambda ----------
def delete_lambda_functions():
    print("Deleting Lambda functions...")
    for func in lambda_client.list_functions()["Functions"]:
        name = func["FunctionName"]
        lambda_client.delete_function(FunctionName=name)
        print(f"Deleted Lambda function: {name}")

def delete_lambda_layers():
    print("Deleting Lambda layers...")
    layers = lambda_client.list_layers()["Layers"]
    for layer in layers:
        name = layer["LayerName"]
        try:
            versions = lambda_client.list_layer_versions(LayerName=name)["LayerVersions"]
            for version in versions:
                lambda_client.delete_layer_version(LayerName=name, VersionNumber=version["Version"])
                print(f"Deleted Layer version: {name}:{version['Version']}")
        except Exception as e:
            print(f"Error deleting layer {name}: {e}")

# ---------- RDS ----------
def delete_rds_instances():
    print("Deleting RDS DB instances...")
    for db in rds.describe_db_instances()["DBInstances"]:
        db_id = db["DBInstanceIdentifier"]
        print(f"Deleting RDS instance: {db_id}")
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)

    print("Deleting manual DB snapshots...")
    for snap in rds.describe_db_snapshots(SnapshotType="manual")["DBSnapshots"]:
        snap_id = snap["DBSnapshotIdentifier"]
        rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id)
        print(f"Deleted DB snapshot: {snap_id}")

# ---------- VPC ----------
def delete_vpcs():
    print("Deleting non-default VPCs and components...")
    vpcs = ec2.describe_vpcs()["Vpcs"]
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        if vpc["IsDefault"]:
            continue
        print(f"Cleaning VPC: {vpc_id}")

        for igw in ec2.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]:
            ec2.detach_internet_gateway(InternetGatewayId=igw["InternetGatewayId"], VpcId=vpc_id)
            ec2.delete_internet_gateway(InternetGatewayId=igw["InternetGatewayId"])
            print(f"Deleted IGW: {igw['InternetGatewayId']}")

        for subnet in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]:
            ec2.delete_subnet(SubnetId=subnet["SubnetId"])
            print(f"Deleted Subnet: {subnet['SubnetId']}")

        for rtb in ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]:
            if not any(assoc.get("Main", False) for assoc in rtb.get("Associations", [])):
                try:
                    ec2.delete_route_table(RouteTableId=rtb["RouteTableId"])
                    print(f"Deleted Route Table: {rtb['RouteTableId']}")
                except: pass

        for acl in ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkAcls"]:
            if not acl["IsDefault"]:
                ec2.delete_network_acl(NetworkAclId=acl["NetworkAclId"])
                print(f"Deleted ACL: {acl['NetworkAclId']}")

        ec2.delete_vpc(VpcId=vpc_id)
        print(f"Deleted VPC: {vpc_id}")

# ---------- DynamoDB ----------
def delete_dynamodb_tables():
    print("Deleting DynamoDB tables...")
    tables = dynamodb.list_tables()["TableNames"]
    for table_name in tables:
        print(f"Deleting table: {table_name}")
        try:
            dynamodb.delete_table(TableName=table_name)
        except Exception as e:
            print(f"Error deleting table {table_name}: {e}")

# ---------- CloudTrail ----------
def delete_cloudtrails():
    print("Deleting CloudTrail trails...")
    trails = cloudtrail.describe_trails()["trailList"]
    for trail in trails:
        name = trail["Name"]
        try:
            cloudtrail.delete_trail(Name=name)
            print(f"Deleted trail: {name}")
        except Exception as e:
            print(f"Error deleting trail {name}: {e}")

# ---------- CloudWatch ----------
def delete_cloudwatch_logs_and_alarms():
    print("Deleting CloudWatch log groups...")
    for group in logs.describe_log_groups()["logGroups"]:
        try:
            logs.delete_log_group(logGroupName=group["logGroupName"])
            print(f"Deleted log group: {group['logGroupName']}")
        except Exception as e:
            print(f"Error deleting log group {group['logGroupName']}: {e}")

    print("Deleting CloudWatch alarms...")
    alarms = cloudwatch.describe_alarms()["MetricAlarms"]
    for alarm in alarms:
        cloudwatch.delete_alarms(AlarmNames=[alarm["AlarmName"]])
        print(f"Deleted alarm: {alarm['AlarmName']}")

# ---------- CloudWatch Events ----------
def delete_eventbridge_rules():
    print("Deleting CloudWatch EventBridge rules...")
    rules = cloudwatch_events.list_rules()["Rules"]
    for rule in rules:
        name = rule["Name"]
        try:
            targets = cloudwatch_events.list_targets_by_rule(Rule=name)["Targets"]
            if targets:
                cloudwatch_events.remove_targets(Rule=name, Ids=[t["Id"] for t in targets])
            cloudwatch_events.delete_rule(Name=name)
            print(f"Deleted EventBridge rule: {name}")
        except Exception as e:
            print(f"Error deleting rule {name}: {e}")
            
# ---------- Glue ----------
glue = boto3.client("glue", region_name=region)

def delete_glue_jobs():
    print("Deleting Glue Jobs...")
    jobs = glue.get_jobs()["Jobs"]
    for job in jobs:
        try:
            glue.delete_job(JobName=job["Name"])
            print(f"Deleted Glue job: {job['Name']}")
        except Exception as e:
            print(f"Error deleting Glue job {job['Name']}: {e}")

def delete_glue_crawlers():
    print("Deleting Glue Crawlers...")
    crawlers = glue.get_crawlers()["Crawlers"]
    for crawler in crawlers:
        try:
            glue.delete_crawler(Name=crawler["Name"])
            print(f"Deleted crawler: {crawler['Name']}")
        except Exception as e:
            print(f"Error deleting crawler {crawler['Name']}: {e}")

def delete_glue_workflows():
    print("Deleting Glue Workflows...")
    workflows = glue.list_workflows()["Workflows"]
    for wf in workflows:
        try:
            glue.delete_workflow(Name=wf)
            print(f"Deleted workflow: {wf}")
        except Exception as e:
            print(f"Error deleting workflow {wf}: {e}")
def delete_glue_triggers():
    print("Deleting Glue Triggers...")
    try:
        triggers = glue.get_triggers()["Triggers"]
        for trigger in triggers:
            name = trigger["Name"]
            glue.delete_trigger(Name=name)
            print(f"Deleted trigger: {name}")
    except Exception as e:
        print(f"Error deleting triggers: {e}")


def delete_glue_databases_and_tables():
    print("Deleting Glue Databases and Tables...")
    databases = glue.get_databases()["DatabaseList"]
    for db in databases:
        db_name = db["Name"]
        if db_name == "default":
            continue  # Skip default database
        try:
            tables = glue.get_tables(DatabaseName=db_name)["TableList"]
            for table in tables:
                glue.delete_table(DatabaseName=db_name, Name=table["Name"])
                print(f"Deleted table: {table['Name']} in DB: {db_name}")
            glue.delete_database(Name=db_name)
            print(f"Deleted database: {db_name}")
        except Exception as e:
            print(f"Error deleting database {db_name}: {e}")


# ---------- Run All ----------
if __name__ == "__main__":
    delete_all_s3_buckets()
    delete_all_sns_topics()
    delete_all_iam_users_roles_groups()
    delete_ec2_resources()
    delete_lambda_functions()
    delete_lambda_layers()
    delete_rds_instances()
    delete_vpcs()
    delete_dynamodb_tables()
    delete_cloudtrails()
    delete_cloudwatch_logs_and_alarms()
    delete_eventbridge_rules()
    delete_glue_jobs()
    delete_glue_crawlers()
    delete_glue_workflows()
    delete_glue_triggers()
    delete_glue_databases_and_tables()

