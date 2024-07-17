cd ../
TEST_MODE=AWS python3 -m unittest discover cfn_policy_validator/tests "test_*.py" -v
cd scripts