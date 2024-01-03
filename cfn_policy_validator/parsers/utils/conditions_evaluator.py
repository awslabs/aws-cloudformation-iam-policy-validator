from cfn_policy_validator import ApplicationError
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema


class ConditionsEvaluator:
	def __init__(self, conditions, node_evaluator):
		self.conditions = conditions
		self.node_evaluator = node_evaluator

	def eval(self, condition_name, visited_nodes: list = None) -> bool:
		visited_nodes = [] if visited_nodes is None else visited_nodes

		intrinsic_function = self.conditions.get(condition_name)
		if intrinsic_function is None:
			raise ApplicationError(f'Unable to find referenced condition in template: {condition_name}')

		validate_schema(intrinsic_function, condition_schema, f'Condition.{condition_name}')

		# there are caveats here if the condition includes a REF, we won't know the exact value until deployment
		# TODO: maybe add a warning finding?
		return self.node_evaluator.eval(intrinsic_function, visited_nodes=visited_nodes)


condition_schema = {
	'type': 'object'
}
