import ai.filter_json_structure
    
    
def test_filter_json_structure_creation():

  filter_options = [
      {'name': 'resource', 'description': 'Filter by the resource on which components depend'},
      {'name': 'vulnerability', 'description': 'Filter by specific vulnerabilities in components'},
      {'name': 'malware', 'description': 'Filter by the presence of malware in components'},
  ]
  
  assert ai.filter_json_structure.generate_filter_json_structure(filter_options) == {
    'filters': {
        'description': 'A complex filter object used to apply multiple attribute-based filters with logical operators',
        'type': 'object',
        'properties': {
            'AND': {
                'description': 'A list of conditions where all must be true (logical AND)',
                'type': 'array',
                'items': {'$ref': '#/definitions/condition'},
            },
            'OR': {
                'description': 'A list of conditions where at least one must be true (logical OR)',
                'type': 'array',
                'items': {'$ref': '#/definitions/condition'},
            },
            'XOR': {
                'description': 'A list of conditions where exactly one must be true (logical XOR)',
                'type': 'array',
                'items': {'$ref': '#/definitions/condition'},
            },
            'NOT': {
                'description': 'A single condition that must not be true (logical NOT)',
                'type': 'array',
                'items': {'$ref': '#/definitions/condition'},
            },
        },
        'definitions': {
            'condition': {
                'description': 'A filter condition which can be an attribute-based filter or another logical operator',
                'type': 'object',
                'oneOf': [
                    {
                        'type': 'object',
                        'properties': {
                            'attribute': {
                                'description': 'The name of the attribute to filter on',
                                'type': 'string',
                                'enum': ['resource', 'vulnerability', 'malware'],
                                'enumDescriptions': [
                                    'Filter by the resource on which components depend',
                                    'Filter by specific vulnerabilities in components',
                                    'Filter by the presence of malware in components',
                                ],
                            },
                            'question': {
                                'description': 'The specific question related to this filter',
                                'type': 'string',
                            },
                        },
                        'required': ['attribute', 'question'],
                    },
                    {
                        'type': 'object',
                        'properties': {
                            'AND': {
                                'description': 'A list of conditions where all must be true (logical AND)',
                                'type': 'array',
                                'items': {'$ref': '#/definitions/condition'},
                            },
                            'OR': {
                                'description': 'A list of conditions where at least one must be true (logical OR)',
                                'type': 'array',
                                'items': {'$ref': '#/definitions/condition'},
                            },
                            'XOR': {
                                'description': 'A list of conditions where exactly one must be true (logical XOR)',
                                'type': 'array',
                                'items': {'$ref': '#/definitions/condition'},
                            },
                            'NOT': {
                                'description': 'A single condition that must not be true (logical NOT)',
                                'type': 'array',
                                'items': {'$ref': '#/definitions/condition'},
                            },
                        },
                    },
                ],
            }
        },
        'additionalProperties': False,
    }
}
