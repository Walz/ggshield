import os
import sys
from copy import deepcopy
from unittest.mock import Mock

import pytest
import yaml
from click import ClickException
from click.testing import CliRunner
from mock import patch

from ggshield.config import (
    Config,
    ensure_path_exists,
    get_auth_config_filepath,
    replace_in_keys,
)


@pytest.fixture(scope="session")
def cli_runner():
    os.environ["GITGUARDIAN_API_KEY"] = os.getenv("GITGUARDIAN_API_KEY", "1234567890")
    return CliRunner()


@pytest.fixture(scope="class")
def cli_fs_runner(cli_runner):
    with cli_runner.isolated_filesystem():
        yield cli_runner


def write(filename, data):
    with open(filename, "w") as file:
        file.write(yaml.dump(data))


class TestUtils:
    def test_replace_in_keys(self):
        data = {"last-found-secrets": {"XXX"}}
        replace_in_keys(data, "-", "_")
        assert data == {"last_found_secrets": {"XXX"}}
        replace_in_keys(data, "_", "-")
        assert data == {"last-found-secrets": {"XXX"}}


class TestUserConfig:
    @patch("ggshield.config.LOCAL_CONFIG_PATHS", ["/tmp/test_local_gitguardian.yml"])
    @patch("ggshield.config.GLOBAL_CONFIG_FILENAMES", [])
    def test_parsing_error(cli_fs_runner, capsys):
        filepath = "/tmp/test_local_gitguardian.yml"
        with open(filepath, "w") as file:
            file.write("Not a:\nyaml file.\n")

        Config()
        out, err = capsys.readouterr()
        sys.stdout.write(out)
        sys.stderr.write(err)

        assert f"Parsing error while reading {filepath}:" in out

    @patch("ggshield.config.GLOBAL_CONFIG_FILENAMES", [])
    def test_display_options(self, cli_fs_runner, local_config_path):
        write(local_config_path, {"verbose": True, "show_secrets": True})

        config = Config()
        assert config.verbose is True
        assert config.show_secrets is True

    @patch("ggshield.config.GLOBAL_CONFIG_FILENAMES", [])
    def test_unknown_option(self, cli_fs_runner, capsys, local_config_path):
        write(local_config_path, {"verbosity": True})

        Config()
        captured = capsys.readouterr()
        assert "Unrecognized key in config" in captured.out

    def test_display_options_inheritance(
        self, cli_fs_runner, local_config_path, global_config_path
    ):
        write(
            local_config_path,
            {
                "verbose": True,
                "show_secrets": False,
                "api_url": "https://gitguardian.com",
            },
        )
        write(
            global_config_path,
            {
                "verbose": False,
                "show_secrets": True,
                "api_url": "https://gitguardian.com/ex",
            },
        )

        config = Config()
        assert config.verbose is True
        assert config.show_secrets is False
        assert config.api_url == "https://gitguardian.com"

    @patch("ggshield.config.GLOBAL_CONFIG_FILENAMES", [])
    def test_exclude_regex(self, cli_fs_runner, local_config_path):
        write(local_config_path, {"paths-ignore": ["/tests/"]})

        config = Config()
        assert r"/tests/" in config.paths_ignore

    def test_accumulation_matches(
        self, cli_fs_runner, local_config_path, global_config_path
    ):
        write(
            local_config_path,
            {
                "matches_ignore": [
                    {"name": "", "match": "one"},
                    {"name": "", "match": "two"},
                ]
            },
        )
        write(
            global_config_path,
            {"matches_ignore": [{"name": "", "match": "three"}]},
        )
        config = Config()
        assert config.matches_ignore == [
            {"match": "three", "name": ""},
            {"match": "one", "name": ""},
            {"match": "two", "name": ""},
        ]


auth_config_filepath = f"{get_auth_config_filepath()}_test"


@patch(
    "ggshield.config.get_auth_config_filepath",
    Mock(return_value=(auth_config_filepath)),
)
class TestAuthConfig:
    default_config = {
        "default-host": "default",
        "default-token-lifetime": 7,  # days
        "hosts": {
            "default": {
                "name": "default",
                "default-token-lifetime": 1,
                "accounts": [
                    {
                        "account-id": 23,
                        "url": "dashboard.gitguardian.com",
                        "token": "62890f237c703c92fbda8236ec2a055ac21332a46115005c976d68b900535fb5",
                        "type": "pat",
                        "token-name": "my_token",
                        "expire-at": "2022-02-23T12:34:56+00:00",
                    }
                ],
            },
            "dashboard.onprem.gitguardian.ovh": {
                "name": None,
                "default-token-lifetime": 0,  # no expiry
                "accounts": [
                    {
                        "account-id": 1,
                        "url": "dashboard.onprem.gitguardian.ovh",
                        "token": "8ecffbaeedcd2f090546efeed3bc48a5f4a04a1196637aef6b3f6bbcfd58a96b",
                        "type": "sat",
                        "token-name": "my_other_token",
                        "expire-at": "2022-02-24T12:34:56+00:00",
                    }
                ],
            },
        },
    }

    @pytest.fixture(autouse=True)
    def clean_file(self):
        try:
            os.remove(auth_config_filepath)
        except FileNotFoundError:
            pass
        yield

    def test_load(self):
        ensure_path_exists("/".join(auth_config_filepath.split("/")[:-1]))
        with open(auth_config_filepath, "w") as f:
            f.write(yaml.dump(self.default_config))

        config = Config()

        assert config.hosts["default"].account.token_name == "my_token"

        config_data = config.auth_config.to_dict()
        replace_in_keys(config_data, old_char="_", new_char="-")
        assert config_data == self.default_config

    @pytest.mark.parametrize("n", [0, 2])
    def test_no_account(self, n):
        raw_config = deepcopy(self.default_config)
        raw_config["hosts"]["default"]["accounts"] = (
            raw_config["hosts"]["default"]["accounts"] * n
        )
        ensure_path_exists("/".join(auth_config_filepath.split("/")[:-1]))
        with open(auth_config_filepath, "w") as f:
            f.write(yaml.dump(raw_config))

        with pytest.raises(
            AssertionError,
            match="Each GitGuardian host should have exactly one account",
        ):
            Config()

    def test_invalid_format(self, capsys):
        ensure_path_exists("/".join(auth_config_filepath.split("/")[:-1]))
        with open(auth_config_filepath, "w") as f:
            f.write("Not a:\nyaml file.\n")

        Config()
        out, err = capsys.readouterr()
        sys.stdout.write(out)
        sys.stderr.write(err)

        assert f"Parsing error while reading {auth_config_filepath}:" in out

    def test_token_not_expiring(self):
        raw_config = deepcopy(self.default_config)
        raw_config["hosts"]["default"]["accounts"][0]["expire-at"] = None
        ensure_path_exists("/".join(auth_config_filepath.split("/")[:-1]))
        with open(auth_config_filepath, "w") as f:
            f.write(yaml.dump(raw_config))

        config = Config()

        assert config.hosts["default"].account.expire_at is None

    def test_update(self):
        config = Config()
        config.default_host = "custom"

        assert Config().default_host != "custom"

        config.save()

        assert Config().default_host == "custom"

    def test_load_file_not_existing(self):
        config = Config()

        assert config.default_host == "https://dashboard.gitguardian.com"
        assert config.default_token_lifetime is None
        assert config.hosts == {}

    def test_save_file_not_existing(self):
        config = Config()
        try:
            os.remove(auth_config_filepath)
        except FileNotFoundError:
            pass

        config.default_host = "custom"
        config.save()
        updated_config = Config()

        assert updated_config.default_host == "custom"


@patch(
    "ggshield.config.get_auth_config_filepath",
    Mock(return_value=(auth_config_filepath)),
)
@pytest.mark.usefixtures("env_vars")
class TestConfig:
    def set_hosts(
        self,
        local_filepath,
        global_filepath,
        local_host=None,
        global_host=None,
        default_host=None,
    ):
        if local_host:
            write(local_filepath, {"api-url": local_host})
        if global_host:
            write(global_filepath, {"api-url": global_host})
        if default_host:
            ensure_path_exists("/".join(auth_config_filepath.split("/")[:-1]))
            with open(auth_config_filepath, "w") as f:
                print("auth_config_filepath", auth_config_filepath)
                data = deepcopy(TestAuthConfig.default_config)
                data["default_host"] = default_host
                if local_host:
                    data["hosts"][local_host] = deepcopy(data["hosts"]["default"])
                if global_host:
                    data["hosts"][global_host] = deepcopy(data["hosts"]["default"])
                f.write(yaml.dump(data))

    @pytest.mark.parametrize(
        [
            "current_host",
            "env_host",
            "local_host",
            "global_host",
            "default_host",
            "expected_host",
        ],
        [
            [
                "https://host1.com",
                "https://host2.com",
                "https://host3.com",
                "https://host4.com",
                "https://host5.com",
                "https://host1.com",
            ],
            [
                None,
                "https://host2.com",
                "https://host3.com",
                "https://host4.com",
                "https://host5.com",
                "https://host2.com",
            ],
            [
                None,
                None,
                "https://host3.com",
                "https://host4.com",
                "https://host5.com",
                "https://host3.com",
            ],
            [
                None,
                None,
                None,
                "https://host4.com",
                "https://host5.com",
                "https://host4.com",
            ],
            [
                None,
                None,
                None,
                None,
                "https://host5.com",
                "https://host5.com",
            ],
        ],
    )
    def test_host_fallbacks(
        self,
        current_host,
        env_host,
        local_host,
        global_host,
        default_host,
        expected_host,
        local_config_path,
        global_config_path,
        monkeypatch,
    ):
        os.environ["GITGUARDIAN_URL"] = env_host
        if "GITGUARDIAN_API_URL" in os.environ:
            del os.environ["GITGUARDIAN_API_URL"]
        self.set_hosts(
            local_host=local_host,
            global_host=global_host,
            default_host=default_host,
            local_filepath=local_config_path,
            global_filepath=global_config_path,
        )
        config = Config()
        config.current_host = current_host

        assert config.gitguardian_hostname == expected_host

    def test_no_host(self, local_config_path, global_config_path):
        self.set_hosts(
            local_host=None,
            global_host=None,
            default_host=None,
            local_filepath=local_config_path,
            global_filepath=global_config_path,
        )
        config = Config()

        assert config.gitguardian_hostname

    def test_host_not_in_auth_config(self):
        config = Config()
        config.current_host = "toto"

        with pytest.raises(ClickException, match="Unrecognized host 'toto'"):
            config.gitguardian_hostname
