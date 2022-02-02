def get_parser_of_type(parsers, parser_type):
	for parser in parsers:
		if isinstance(parser, parser_type):
			return parser

	return None
