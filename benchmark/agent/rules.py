"""Protocol-field baseline and exact, development-frozen scoring normalization."""
import re
import unicodedata


def normalize(value):
    if value is None:
        return ''
    return ''.join(c for c in unicodedata.normalize('NFKC', str(value)).casefold() if c.isalnum())


def present(value):
    return value is not None and str(value).strip().casefold() not in {
        '', '[masked]', 'unknown', 'null', 'none', 'n/a', 'not found'}


def explicit_models(evidence):
    """Only declared model/product/order fields; never status/type/revision values."""
    candidates = []
    for item in evidence['responses']:
        response = item['response']
        kind = response.get('kind')
        if kind == 'modbus_device_identification':
            objects = {o['object_id']: o['value'] for o in response['objects']}
            for priority, oid in enumerate([5, 1, 4]):
                if present(objects.get(oid)):
                    candidates.append((priority, str(objects[oid]), f'modbus.object.{oid}'))
        elif kind in {'enip_list_identity', 'enip_cip_identity'}:
            for identity in response['identities']:
                if present(identity.get('product_name')):
                    candidates.append((0, identity['product_name'], 'enip.product_name'))
                if present(identity.get('product_code')):
                    # This marker prevents interpreting a bare number in another field as a product code.
                    candidates.append((1, 'product_code:' + str(identity['product_code']), 'enip.product_code'))
        elif kind == 's7_module_identification':
            for entry in response['entries']:
                if entry.get('index') == 1 and present(entry.get('order_number')):
                    candidates.append((0, entry['order_number'], 's7.szl_0011.index_1.order_number'))
    return candidates


def rule_predict(evidence):
    candidates = explicit_models(evidence)
    if not candidates:
        return {'pred_model': None, 'accepted': False, 'reason': 'no_explicit_model_field'}
    priority = min(x[0] for x in candidates)
    top = {normalize(value): (value, source) for p, value, source in candidates if p == priority}
    if len(top) != 1:
        return {'pred_model': None, 'accepted': False, 'reason': 'conflicting_explicit_model_fields'}
    value, source = next(iter(top.values()))
    return {'pred_model': value, 'accepted': True, 'reason': source}


def alias_variants(value, protocol):
    """Only deterministic formatting variants, with no fuzzy/substring scoring."""
    yield normalize(value)
    if protocol == 'enip':
        # Identity product names can append a hardware-series / firmware revision suffix.
        stripped = re.sub(r'\s+[A-Z]/\d+(?:\.\d+)*\s*$', '', str(value))
        if stripped != str(value):
            yield normalize(stripped)
