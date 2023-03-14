#!/bin/bash
## Place new license into /lambda_functions/analyzer/

## run this script to auto update license from nextron


# unzip Dependencies.zip to temp_dep/
mkdir /binaryalert/lambda_functions/analyzer/temp_dep
unzip /binaryalert/lambda_functions/analyzer/dependencies -d /binaryalert/lambda_functions/analyzer/temp_dep/
wait
mv /binaryalert/lambda_functions/analyzer/*.lic /binaryalert/lambda_functions/analyzer/temp_dep/ || echo "No New License File Found"
# make thor-util executable
chmod u+x /binaryalert/lambda_functions/analyzer/temp_dep/thor-util
# update to latest ruleset using thor-util
/binaryalert/lambda_functions/analyzer/temp_dep/thor-util update
wait
# upgrade to lastest THOR version using thor-util
/binaryalert/lambda_functions/analyzer/temp_dep/thor-util upgrade
wait
rm -rf /binaryalert/lambda_functions/analyzer/dependencies.zip
cd /binaryalert/lambda_functions/analyzer/temp_dep/ && zip -ro ../dependencies.zip .
cd /binaryalert
rm -rf /binaryalert/lambda_functions/analyzer/temp_dep/

./manage.py apply
./manage.py build
wait
## ./dashboard.py if custom dashboard created, it will repopulate here
./dashboard.py
echo "THOR has been updated"
