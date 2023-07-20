import json


ANNOTATION_INPUT = 'input'
ANNOTATION_PARSER_FIELD = 'parser_field'
ANNOTATION_PARSER_METADATA = 'parser_metadata'


class SymbolAnnotation(object):
    """
    Since the propagation of Annotation is janky, we use the symbol name encoding to pass info
    """
    @staticmethod
    def encode_stream_input_annotation(data_api, offset, size, dst_addr):
        tag = [
            {
                'type': ANNOTATION_INPUT,
                'data_api': data_api,
                'offset': offset,
                'size': size,
                'dst_addr': dst_addr,
            }
        ]
        return json.dumps(tag)

    @staticmethod
    def encode_parser_field_annotation(op, addr, size):
        tag = [
            {
                'type': ANNOTATION_PARSER_FIELD,
                'op': op,
                'addr': addr,
                'size': size,
            }
        ]
        return json.dumps(tag)

    @staticmethod
    def encode_parser_metadata_annotation(data_api, desc, addr, size):
        tag = [
            {
                'type': ANNOTATION_PARSER_METADATA,
                'data_api': data_api,
                'desc': desc,
                'addr': addr,
                'size': size,
            }
        ]
        return json.dumps(tag)

    @staticmethod
    def encode_annotations(tags):
        return json.dumps(tags)

    @staticmethod
    def decode_annotations(symbol_name):
        try:
            tags = json.loads(symbol_name)
        except Exception:
            return []

        return tags

    @staticmethod
    def get_all_tags(bvs):
        if bvs is None or not hasattr(bvs, 'depth'):
            return []

        if bvs.depth == 1:
            if bvs.op != 'BVS':
                return []

            name = bvs.args[0]
            name = name[:name.rfind('_')]
            symbol_name = name[:name.rfind('_')]
            return SymbolAnnotation.decode_annotations(symbol_name)

        tags = []
        for arg in bvs.args:
            for tag in SymbolAnnotation.get_all_tags(arg):
                if tag not in tags:
                    tags.append(tag)

        return tags
