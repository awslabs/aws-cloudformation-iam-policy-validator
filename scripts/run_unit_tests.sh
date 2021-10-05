cd ../
TEST_MODE=OFFLINE python3 -m unittest discover cfn_policy_validator/tests "test_*.py" -v
cd scripts