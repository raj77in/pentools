!#/bin/bash

apt install awscli
aws configure

# Start Server 2016 and configure
privkey=""
ID=ami-08aa543413d7bdc57
aws ec2 run-instances --image-id $ID --count 1 --instance-type t2.micro --key-name aka --security-group-ids sg-047fcbab42580b283 --subnet-id  subnet-854a1eda --user-data file://ignored/user_data-ad.txt
id=""
while [ -z $id ]
do
  id=$(aws ec2 describe-instances --filters Name=instance-type,Values=t2.micro Name=instance-state-name,Values=running --query "Reservations[].Instances[].InstanceId" --output text)
  sleep 1
done

pw=""
while [ -z $pw ]
do
pw=$(aws ec2 get-password-data --instance-id $id --priv-launch-key $privkey --query 'PasswordData' --output text)
sleep 1
done
ip=""
while [ -z $ip ]
do
ip=$(aws ec2 describe-instances --instance-ids $id --query 'Reservations[*].Instances[*].PublicIpAddress' --output text)
done

xfreerdp /p:"$pw"  /u:Administrator /v:"$ip" /dynamic-resolution +clipboard /cert:ignore +auto-reconnect

