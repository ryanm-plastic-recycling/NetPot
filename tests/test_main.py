import honeysentinel.__main__ as main_module


def test_main_loads_default_dotenv(monkeypatch) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_load_dotenv(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.delenv("DOTENV_PATH", raising=False)
    monkeypatch.setattr(main_module, "load_dotenv", fake_load_dotenv)
    monkeypatch.setattr(main_module, "create_app", lambda config_path: "app")
    monkeypatch.setattr(main_module.uvicorn, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module.sys, "argv", ["honeysentinel"])

    main_module.main()

    assert calls == [((), {})]


def test_main_loads_dotenv_from_env_path(monkeypatch) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_load_dotenv(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setenv("DOTENV_PATH", "/tmp/custom.env")
    monkeypatch.setattr(main_module, "load_dotenv", fake_load_dotenv)
    monkeypatch.setattr(main_module, "create_app", lambda config_path: "app")
    monkeypatch.setattr(main_module.uvicorn, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module.sys, "argv", ["honeysentinel"])

    main_module.main()

    assert calls == [(("/tmp/custom.env",), {"override": False})]
