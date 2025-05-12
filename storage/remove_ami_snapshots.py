import boto3

def deregister_amis_from_file(file_path):
    # Read the list of AMIs from the file
    with open(file_path, 'r') as file:
        ami_ids = [line.strip() for line in file.readlines()]

    # Initialize the AWS Boto3 clients for EC2 and EBS
    ec2_client = boto3.client('ec2')
    ec2_resource = boto3.resource('ec2')

    # Iterate through the AMI IDs and deregister each one
    for ami_id in ami_ids:
        print(f"Deregistering AMI: {ami_id}")
        
        # Describe snapshots associated with the AMI
        response = ec2_client.describe_images(ImageIds=[ami_id])
        images = response['Images']
        
        # Deregister the AMI
        ec2_client.deregister_image(ImageId=ami_id)
        
        # Delete snapshots associated with the AMI
        for image in images:
            block_devices = image['BlockDeviceMappings']
            for block_device in block_devices:
                if 'Ebs' in block_device:
                    snapshot_id = block_device['Ebs']['SnapshotId']
                    print(f"Deleting Snapshot: {snapshot_id}")
                    snapshot = ec2_resource.Snapshot(snapshot_id)
                    snapshot.delete()
        
        print(f"Deregistered AMI: {ami_id}")

# Specify the path to the file containing the AMI IDs
file_path = r'C:\Users\username\desktop\aami_list.txt'

# Call the function to deregister the AMIs and delete associated snapshots
deregister_amis_from_file(file_path) 
