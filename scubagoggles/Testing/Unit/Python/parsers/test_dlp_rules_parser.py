"""Tests for the DlpRulesParser class.
"""

import pytest

from scubagoggles.parsers.dlp_rules_parser import DlpRulesParser

# pylint: disable=too-few-public-methods


def _rule(detector: str, likelihood: str, counts: str = '') -> dict:

    """Builds a rule carrying a single DLP content condition, in the form
    Google returns from the Policy API.
    """

    condition = (f'all_content.matches_dlp_detector("{detector}", '
                 f'google.privacy.dlp.v2.Likelihood.{likelihood}{counts}')
    condition += ')'

    return {'condition': {'contentCondition': condition}}


class TestDlpRulesParser:

    """This class contains unit tests for the DlpRulesParser class.
    """

    # The test module needs to access "internal" methods.
    # pylint: disable=protected-access

    _both_counts = ', {minimum_match_count: 1, minimum_unique_match_count: 1}'

    @pytest.mark.parametrize('counts',
                             [_both_counts,
                              '',
                              ', {minimum_match_count: 1}',
                              ', {minimum_unique_match_count: 1}'],
                             ids = ['both counts',
                                    'no counts',
                                    'minimum only',
                                    'unique only'])
    def test_condition_counts_optional(self, counts):

        """A condition may leave out either match count, or both.  Google
        omits them for rules whose action has nowhere to set one, and the
        term then triggers on a single match, which meets the baseline.
        """

        rule = _rule('CREDIT_CARD_NUMBER', 'LIKELY', counts)

        assert (DlpRulesParser._check_condition(rule)
                == {'CREDIT_CARD_NUMBER'})

    @pytest.mark.parametrize(
        'detector,likelihood,counts',
        [('CREDIT_CARD_NUMBER', 'LIKELY',
          ', {minimum_match_count: 5, minimum_unique_match_count: 1}'),
         ('CREDIT_CARD_NUMBER', 'POSSIBLE', _both_counts),
         ('EMAIL_ADDRESS', 'LIKELY', _both_counts)],
        ids = ['count above one', 'likelihood too low', 'detector not required'])
    def test_condition_rejected(self, detector, likelihood, counts):

        """A term that does not meet the baseline contributes no detector.
        """

        rule = _rule(detector, likelihood, counts)

        assert not DlpRulesParser._check_condition(rule)
