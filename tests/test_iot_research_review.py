import json
from scripts.iot_research_review import sanitize, source_context


def test_structured_redaction_preserves_paths_and_usage_keys():
    path = 'OpenWrt/openwrt-18.06.2/files/etc/config/wireless'
    value = {'file': path, 'completion_tokens_details': {'reasoning_tokens': 12},
             'content': json.dumps({'evidence': [path + ':10']})}
    result = sanitize(value)
    assert result['file'] == path
    assert result['completion_tokens_details']['reasoning_tokens'] == 12
    assert json.loads(result['content'])['evidence'] == [path + ':10']


def test_shadow_redaction_keeps_algorithm_metadata(tmp_path):
    path = tmp_path / 'shadow'
    path.write_text('root:$1$salt$privatehash:0:0:99999:7:::\n')
    context = source_context(path, 'etc/shadow')
    assert 'privatehash' not in json.dumps(context)
    assert 'salt' not in context['context']
    assert context['password_hash_algorithms'] == [
        {'file': 'etc/shadow', 'line': 1, 'algorithm': 'md5crypt'}]
