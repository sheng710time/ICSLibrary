import collections
from rules import alias_variants

def map_label(value, fold, protocol, aliases):
    options = set()
    for key in alias_variants(value, protocol):
        options.update(aliases[f'{fold}:{protocol}'].get(key, []))
    if len(options) == 1:
        return next(iter(options)), 'unique_exact_alias'
    return 'UNMAPPED::' + str(value), 'ambiguous_alias' if options else 'unseen_alias'


def metrics_for(rows):
    counts = collections.Counter(r['outcome'] for r in rows)
    n = len(rows)
    accepted = counts['correct_confirmation'] + counts['wrong_confirmation']
    failed = counts['program_failure']
    values = {'n_correct': counts['correct_confirmation'], 'n_wrong': counts['wrong_confirmation'],
        'n_abstain': counts['abstain'], 'n_failures': failed,
        'correct_confirmation_rate': counts['correct_confirmation'] / n if not failed else '',
        'wrong_confirmation_rate': counts['wrong_confirmation'] / n if not failed else '',
        'abstention_rate': counts['abstain'] / n if not failed else '',
        'coverage': accepted / n if not failed else '',
        'accepted_error_rate': counts['wrong_confirmation'] / accepted if accepted and not failed else 'NA'}
    if not failed:
        assert abs(sum(values[k] for k in ['correct_confirmation_rate', 'wrong_confirmation_rate', 'abstention_rate']) - 1) < 1e-10
    return values
