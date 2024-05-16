import json
import pathlib
import subprocess
from importlib import resources

from wireshark_digest_to_sqlite import anonymize, scripts

PCAP_CURL_SH = resources.files(scripts) / "pcap_curl.sh"


def json_to_single_line(json_str: str) -> str:
    """
    Rewrite a json file with no indents and new lines. Equivalent to:
    jq --indent 0
    """
    loaded = json.loads(json_str)
    return json.dumps(loaded, ensure_ascii=False)


def main():
    try:
        subprocess.run(["sudo", "bash", "-c", PCAP_CURL_SH], check=True)
    except subprocess.CalledProcessError:
        raise Exception("Failed to execute capture script.")

    curl_anon = pathlib.Path("curl_anon.json")
    anonymize.main(pathlib.Path("curl.json"), curl_anon)

    pathlib.Path("curl_anon_single_line.json").write_text(
        json_to_single_line(curl_anon.read_text())
    )


if __name__ == "__main__":
    main()
