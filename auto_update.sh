#!/bin/bash

exec 3>&1 &>/dev/null
# unzip Dependencies.zip to temp_dep/
mkdir /binaryalert/lambda_functions/analyzer/temp_dep
unzip /binaryalert/lambda_functions/analyzer/dependencies -d /binaryalert/lambda_functions/analyzer/temp_dep/
wait
mv /binaryalert/lambda_functions/analyzer/*.lic /binaryalert/lambda_functions/analyzer/temp_dep/ || echo "No New License File Found" >&3
# make thor-util executable
chmod u+x /binaryalert/lambda_functions/analyzer/temp_dep/thor-util
# upgrade to lastest THOR version using thor-util
echo "Launching THOR util to update licenses, YARA rules, and THOR" >&3
# to update rules use update, to upgrade thor use upgrade
/binaryalert/lambda_functions/analyzer/temp_dep/thor-util update >&3
wait
rm -rf /binaryalert/lambda_functions/analyzer/dependencies.zip
cd /binaryalert/lambda_functions/analyzer/temp_dep/ && zip -ro ../dependencies.zip .
cd /binaryalert
rm -rf /binaryalert/lambda_functions/analyzer/temp_dep/

./manage.py apply >&3
./manage.py build
wait
# if custom dashboard was created it will redeploy it here
./dashboard.py
echo "THOR analyzer lambdas have been upgraded and redeployed" >&3
