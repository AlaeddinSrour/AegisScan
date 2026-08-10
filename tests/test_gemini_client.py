import pytest
from unittest.mock import patch, MagicMock
from src.gemini_client import call_gemini_with_failover
from src.models import ReviewReport, ReviewIssue
import src.gemini_client as gc


def test_default_models_use_current_gemini_replacements():
    assert gc.FAILOVER_MODELS == [
        "gemini-3.6-flash",
        "gemini-3.5-flash",
    ]

@patch('src.gemini_client.time.sleep')
@patch('src.gemini_client.API_TIMEOUT_SECONDS', 1)
@patch('src.gemini_client.MAX_RETRIES', 3)
def test_successful_first_model(mock_sleep):
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_report = ReviewReport(analysis_scratchpad="test", issues=[])
    mock_response.parsed = mock_report
    mock_client.models.generate_content.return_value = mock_response

    result = call_gemini_with_failover(mock_client, "prompt")
    assert result == mock_report
    assert mock_client.models.generate_content.call_count == 1
    config = mock_client.models.generate_content.call_args.kwargs["config"]
    assert config.http_options.timeout == 1000
    assert config.response_schema is None
    assert config.response_json_schema["additionalProperties"] is False


@patch('src.gemini_client.time.sleep')
@patch('src.gemini_client.MAX_RETRIES', 1)
def test_json_schema_dict_response_is_validated_into_review_report(mock_sleep):
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.parsed = {"analysis_scratchpad": "validated", "issues": []}
    mock_client.models.generate_content.return_value = mock_response

    result = call_gemini_with_failover(mock_client, "prompt")

    assert isinstance(result, ReviewReport)
    assert result.analysis_scratchpad == "validated"

@patch('src.gemini_client.time.sleep')
@patch('src.gemini_client.API_TIMEOUT_SECONDS', 1)
@patch('src.gemini_client.MAX_RETRIES', 2)
def test_failover_to_second_model(mock_sleep):
    mock_client = MagicMock()
    
    mock_success_response = MagicMock()
    mock_report = ReviewReport(analysis_scratchpad="test2", issues=[])
    mock_success_response.parsed = mock_report
    
    # First model fails, second succeeds
    mock_client.models.generate_content.side_effect = [Exception("error"), mock_success_response]
    
    with patch('src.gemini_client.FAILOVER_MODELS', ['model1', 'model2']):
        # If MAX_RETRIES=2, it will try model1 twice, so side_effect needs 3 elements: error, error, success
        mock_client.models.generate_content.side_effect = [Exception("err1"), Exception("err2"), mock_success_response]
        result = call_gemini_with_failover(mock_client, "prompt")
        
        assert result == mock_report
        assert mock_client.models.generate_content.call_count == 3

@patch('src.gemini_client.time.sleep')
@patch('src.gemini_client.API_TIMEOUT_SECONDS', 1)
@patch('src.gemini_client.MAX_RETRIES', 1)
@patch('src.gemini_client.FAILOVER_MODELS', ['model-a'])
def test_all_models_exhausted_raises_runtime_error(mock_sleep):
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = Exception("error")

    with pytest.raises(RuntimeError) as exc_info:
        call_gemini_with_failover(mock_client, "prompt")
    
    assert "All Gemini models failed" in str(exc_info.value)
    assert "model-a: error" in str(exc_info.value)


@patch('src.gemini_client.time.sleep')
@patch('src.gemini_client.MAX_RETRIES', 1)
@patch('src.gemini_client.FAILOVER_MODELS', ['model-a'])
def test_provider_error_redacts_api_key(mock_sleep):
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = Exception(
        "request failed at https://example.test?key=super-secret&x=1"
    )

    with pytest.raises(RuntimeError) as exc_info:
        call_gemini_with_failover(mock_client, "prompt")

    assert "super-secret" not in str(exc_info.value)
    assert "[REDACTED]" in str(exc_info.value)


@patch('src.gemini_client.time.sleep')
@patch('src.gemini_client.MAX_RETRIES', 3)
@patch('src.gemini_client.FAILOVER_MODELS', ['model-a', 'model-b'])
def test_non_retryable_client_error_attempts_each_model_once(mock_sleep):
    class ClientFailure(Exception):
        code = 401

    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = ClientFailure("invalid API key")

    with pytest.raises(RuntimeError, match="invalid API key"):
        call_gemini_with_failover(mock_client, "prompt")

    assert mock_client.models.generate_content.call_count == 2
    mock_sleep.assert_not_called()

@patch('src.gemini_client.time.sleep')
@patch('src.gemini_client.API_TIMEOUT_SECONDS', 1)
@patch('src.gemini_client.MAX_RETRIES', 2)
def test_retry_on_empty_parsed_response(mock_sleep):
    mock_client = MagicMock()
    
    mock_empty_response = MagicMock()
    mock_empty_response.parsed = None
    
    mock_success_response = MagicMock()
    mock_report = ReviewReport(analysis_scratchpad="test3", issues=[])
    mock_success_response.parsed = mock_report
    
    mock_client.models.generate_content.side_effect = [mock_empty_response, mock_success_response]
    
    result = call_gemini_with_failover(mock_client, "prompt")
    
    assert result == mock_report
    assert mock_client.models.generate_content.call_count == 2
