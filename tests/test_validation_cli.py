import json

from threatlens import __main__ as cli


def test_validation_command_does_not_initialize_database(monkeypatch, tmp_path, capsys):
    dataset = tmp_path / "labels.jsonl"
    dataset.write_text(
        json.dumps({
            "indicator": "example.invalid",
            "ioc_type": "domain",
            "label": "unknown",
            "evidence_source": None,
            "evidence_url": None,
            "reviewed_at": None,
            "notes": "Synthetic placeholder",
        }) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        ["threatlens", "validate-dataset", "--dataset", str(dataset)],
    )

    def fail_if_called():
        raise AssertionError("Validation must not initialize the production database")

    monkeypatch.setattr(cli, "initialize_database", fail_if_called)

    assert cli.main() == 0
    output = capsys.readouterr().out
    assert "Records loaded: 1" in output
    assert "Evaluated samples: 0" in output


def test_validation_json_output_is_machine_readable(monkeypatch, tmp_path, capsys):
    dataset = tmp_path / "labels.jsonl"
    dataset.write_text(
        json.dumps({
            "indicator": "example.invalid",
            "ioc_type": "domain",
            "label": "unknown",
            "evidence_source": None,
            "evidence_url": None,
            "reviewed_at": None,
            "notes": "Synthetic placeholder",
        }) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        ["threatlens", "validate-dataset", "--dataset", str(dataset), "--format", "json"],
    )
    monkeypatch.setattr(
        cli,
        "initialize_database",
        lambda: (_ for _ in ()).throw(
            AssertionError("Validation must not initialize the production database")
        ),
    )

    assert cli.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ok"
    assert result["counts"]["evaluated"] == 0
    assert result["metrics"]["precision"] is None


def test_validation_rejects_invalid_threshold(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        ["threatlens", "validate-dataset", "--threshold", "101"],
    )

    assert cli.main() == 2
    assert "Threshold must be from 0 to 100" in capsys.readouterr().err
