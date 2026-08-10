import pytest
from src.safety import is_suggested_fix_safe

def test_safety_validator_safe_code():
    suggested_fix = "subprocess.run(['git', 'status'], shell=False)"
    is_safe, reason = is_suggested_fix_safe(suggested_fix)
    assert is_safe is True
    assert reason == ""

def test_safety_validator_blocks_eval():
    suggested_fix = "result = eval('1 + 1')"
    is_safe, reason = is_suggested_fix_safe(suggested_fix)
    assert is_safe is False
    assert "eval" in reason.lower()

def test_safety_validator_blocks_os_system():
    suggested_fix = "os.system('rm -rf /')"
    is_safe, reason = is_suggested_fix_safe(suggested_fix)
    assert is_safe is False
    assert "unvetted sub-process" in reason.lower()

def test_safety_validator_blocks_permissive_chmod():
    suggested_fix = "os.chmod('file.txt', 0o777)"
    is_safe, reason = is_suggested_fix_safe(suggested_fix)
    assert is_safe is False
    assert "permissive" in reason.lower()

def test_safety_validator_allows_subprocess_module():
    suggested_fix = "import subprocess\nsubprocess.Popen(['ls'])"
    is_safe, reason = is_suggested_fix_safe(suggested_fix)
    assert is_safe is True

# --- New tests for enhanced safety patterns ---

def test_safety_validator_blocks_shell_true():
    suggested_fix = "subprocess.Popen(cmd, shell=True)"
    is_safe, reason = is_suggested_fix_safe(suggested_fix)
    assert is_safe is False
    assert "shell=True" in reason

def test_safety_validator_blocks_dunder_import():
    suggested_fix = "__import__('os').system('id')"
    is_safe, reason = is_suggested_fix_safe(suggested_fix)
    assert is_safe is False
    assert "__import__" in reason

def test_safety_validator_blocks_pickle_loads():
    suggested_fix = "data = pickle.loads(user_input)"
    is_safe, reason = is_suggested_fix_safe(suggested_fix)
    assert is_safe is False
    assert "pickle" in reason.lower()

def test_safety_validator_blocks_unsafe_yaml_load():
    suggested_fix = "config = yaml.load(data)"
    is_safe, reason = is_suggested_fix_safe(suggested_fix)
    assert is_safe is False
    assert "yaml.load" in reason

def test_safety_validator_allows_yaml_safe_load():
    suggested_fix = "config = yaml.safe_load(data)"
    is_safe, reason = is_suggested_fix_safe(suggested_fix)
    assert is_safe is True

def test_safety_validator_allows_yaml_load_with_safeloader():
    suggested_fix = "config = yaml.load(data, Loader=yaml.SafeLoader)"
    is_safe, reason = is_suggested_fix_safe(suggested_fix)
    assert is_safe is True

def test_safety_validator_blocks_marshal_loads():
    suggested_fix = "obj = marshal.loads(raw_bytes)"
    is_safe, reason = is_suggested_fix_safe(suggested_fix)
    assert is_safe is False
    assert "marshal" in reason.lower()


@pytest.mark.parametrize(
    "suggested_fix",
    [
        "subprocess.run(user_input)",
        "subprocess.run(shlex.split(cmd), shell=False)",
        "shutil.rmtree(project_root)",
        "requests.get(user_supplied_url)",
    ],
)
def test_safety_validator_blocks_unprovable_side_effects(suggested_fix):
    is_safe, _ = is_suggested_fix_safe(suggested_fix)
    assert is_safe is False
