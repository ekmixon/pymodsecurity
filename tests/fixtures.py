import pytest
import os

from ModSecurity import ModSecurity
from ModSecurity import Rules
from ModSecurity import Transaction
from ModSecurity import ModSecurityIntervention


@pytest.fixture
def modsec():
    return ModSecurity()


@pytest.fixture
def rules(tmpdir):
    rules = Rules()
    rules.loadFromUri('tests/config-logs.conf')
    rules.load(f'SecTmpDir {str(tmpdir)}')
    rules.load(f'SecDataDir {str(tmpdir)}')
    rules.load(f'SecDebugLog {str(tmpdir)}/modsec_debug.log')
    return rules


@pytest.fixture
def basic_rules(rules, tmpdir):
    log_filename = tmpdir.join('modsec_audit.log')
    rules.loadFromUri('tests/basic_rules.conf')
    rules.load(f'SecAuditLog {str(log_filename)}')
    return rules


@pytest.fixture
def transaction(modsec, rules):
    return Transaction(modsec, rules)

@pytest.fixture
def intervention():
    return ModSecurityIntervention()

@pytest.fixture
def callback_test_rules(rules):
    rule = (
        'SecRuleEngine On\n'
        + 'SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" "phase:0,allow,id:161,msg:\'test\'"'
    )

    assert rules.load(rule) > 0, rules.getParserError() or 'Failed to load rule'