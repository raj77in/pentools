!#/bin/bash

apt install awscli
aws configure

# Start Server 2016 and configure
AWS_privkey="${AWS_privkey:-~/.ssh/id_rsa}"
AWS_ID="${AWS_ID:-ami-08aa543413d7bdc57}"
AWS_SG="${AWS_SG:-INVALID}"
AWS_SUBNET="${AWS_SUBNET:-INVALID}"
AWS_KEY="${AWS_KEY:-INVALID}"
AWS_ITYPE="${AWS_ITYPE:-t3.micro}"

## Generate param file
# aws ec2 run-instances --generate-cli-skeleton input > AD.json

aws ec2 run-instances --image-id $AWS_ID --count 1 --instance-type $AWS_ITYPE --key-name $AWS_KEY --security-group-ids $AWS_SG --subnet-id  $AWS_SUBNET  --user-data file://user-data/AD.ps1
# aws ec2 request-spot-instances --spot-price "0.003" --instance-count 1 --type "persistent" --launch-specification file://param.json --instance-interruption-behavior "stop" --profile ""
id="" ; while [ -z $id ]
do
  id=$(aws ec2 describe-instances --filters Name=instance-type,Values=$AWS_ITYPE Name=instance-state-name,Values=running Name=image-id,Values=$AWS_ID --query "Reservations[].Instances[].InstanceId" --output text)
  echo -n '.'
  sleep 1
done
echo; echo $id

pw="" ; while [ -z $pw ]
do
  pw=$(aws ec2 get-password-data --instance-id $id --priv-launch-key $AWS_privkey --query 'PasswordData' --output text)
  echo -n '.'
  sleep 1
done
echo; echo $pw


ip="" ; while [ -z $ip ]
do
  echo -n '.'
  ip=$(aws ec2 describe-instances --instance-ids $id --query 'Reservations[*].Instances[*].PublicIpAddress' --output text)
done
echo; echo $ip

#Set error to non zero. Hopefully this file does not exist :)
ls lkjlakjsldkfjasdlkfj 2>/dev/null ; while [ $? != 0 ]
do
   xfreerdp /p:"$pw"  /u:Administrator /v:"$ip" /dynamic-resolution +clipboard /cert:ignore +auto-reconnect
done


aws ec2 run-instances --image-id $AWS_IDWin10 --count 1 --instance-type $AWS_ITYPE --key-name $AWS_KEY --security-group-ids $AWS_SG --subnet-id  $AWS_SUBNET  --user-data file://user-data/clients.ps1
id="" ; while [ -z $id ]; do   id=$(aws ec2 describe-instances --filters Name=instance-type,Values=$AWS_ITYPE Name=instance-state-name,Values=running Name=image-id,Values=$AWS_IDWin10 --query "Reservations[].Instances[].InstanceId" --output text);   echo -n '.';   sleep 1; done
pw="" ; while [ -z $pw ]
do
  pw=$(aws ec2 get-password-data --instance-id $id --priv-launch-key $AWS_privkey --query 'PasswordData' --output text)
  echo -n '.'
  sleep 1
done
echo; echo $pw


ip="" ; while [ -z $ip ]
do
  echo -n '.'
  ip=$(aws ec2 describe-instances --instance-ids $id --query 'Reservations[*].Instances[*].PublicIpAddress' --output text)
done
echo; echo $ip

#Set error to non zero. Hopefully this file does not exist :)
ls lkjlakjsldkfjasdlkfj 2>/dev/null ; while [ $? != 0 ]
do
   xfreerdp /p:"$pw"  /u:Administrator /v:"$ip" /dynamic-resolution +clipboard /cert:ignore +auto-reconnect
done
