#!/usr/bin/env python3

import ssl
import json
import socket
import base64
import pathlib
import os.path
import hashlib
import argparse
import subprocess
import configparser
from getpass import getpass
from types import SimpleNamespace
from urllib.parse import urlparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen

"""An icinga check_command wrapper to icinga api for submitting passive check results"""


def verify_url(url):
    """parse and verify url validity"""

    try:
        parsed = urlparse(url)
        if bool(parsed.scheme) and bool(parsed.netloc):
            return parsed
        return None
    except Exception:
        return None


def download_certificate(args, url):
    """download tls certificate from https url and display fingerprint for verification"""

    # download certificate
    ctx = ssl._create_unverified_context()
    port = url.port if url.port is not None else 443
    with socket.create_connection((url.hostname, port)) as sock:
        with ctx.wrap_socket(sock, server_hostname=url.hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)

    # calculate fingerprint
    fp = hashlib.sha256(cert_der).hexdigest()

    def format_fingerprint(fingerprint_hex: str) -> str:
        return ":".join(
            fingerprint_hex[i : i + 2] for i in range(0, len(fingerprint_hex), 2)
        ).upper()

    # ask for confirmation
    print("Please verfiy TLS fingerprint with certificate from master:")
    print(format_fingerprint(fp))
    print(
        "Hint: openssl x509 -in /var/lib/icinga2/certs/<hostname>.crt -noout -fingerprint -sha256"
    )
    yesno = input("Accept? [y/N]") == "y" or False
    if not yesno:
        raise Exception("Untrusted certificate, unable to continue.")

    # write accepted certificate to file in pem format
    cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
    with open(args.cacert, "w+") as fd:
        fd.write(cert_pem)
        fd.flush()
        fd.close()

    return fp


def parse_args():
    """Parse command line arguments, capture known and unknown args"""

    parser = argparse.ArgumentParser(description=__doc__)
    configpath = pathlib.Path(__file__).parent.resolve() / "config.ini"
    capath = pathlib.Path(__file__).parent.resolve() / "master.pem"
    parser.add_argument(
        "--config",
        type=pathlib.Path,
        default=configpath,
        help="Path where to store/load config from. [default=config.ini]",
    )
    parser.add_argument(
        "--cacert",
        type=pathlib.Path,
        default=capath,
        help="Path where to store/load ca certificate from. [default=master.pem]",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Optional timeout for execution in seconds.",
    )
    parser.add_argument(
        "-s",
        type=str,
        required=True,
        metavar="SERVICE NAME",
        help="Specify service name",
    )
    parser.add_argument(
        "--ttl", type=int, default=None, help="TTL argument to pass to icinga api"
    )
    parser.add_argument(
        "check_command",
        nargs=argparse.REMAINDER,
        help="Check_command to execute with arguments.",
    )

    return parser.parse_args()


def load_config(args):
    """Load config from file, init with necessary values"""

    # prep config parser
    config = configparser.ConfigParser()
    default = config["DEFAULT"]
    if "TLS" not in config:
        config["TLS"] = {}
    authconfig = config["TLS"]

    # load config from file
    if os.path.isfile(args.config):
        config.read(args.config)
        if not {"url", "user", "password", "check_source"}.issubset(default) or not {
            "fingerprint"
        }.issubset(authconfig):
            raise Exception(
                "Invalid configuration file. Delete config file and try again."
            )

        return config

    # request api url until a valid url is provided
    durl = "https://localhost:5665"
    url = None
    while url is None:
        # ask for url
        default["url"] = input(f"Icinga API master url (default: {durl}):") or durl
        default["url"] += "/v1/actions/process-check-result"

        # parse and verify url
        url = verify_url(default["url"])
        if url is None:
            print("[ERROR] Invalid url, please specify a valid url.")

    # download certificate and validate fingerprint
    if url.scheme == "https":
        authconfig["fingerprint"] = download_certificate(args, url)

    # request check_source property
    hostname = socket.getfqdn()
    default["check_source"] = (
        input(f"Input host name (default:{hostname}):") or hostname
    )

    # request username
    duser = "passive"
    default["user"] = input(f"Icinga API username (default: {duser}):") or duser

    # request password
    default["password"] = getpass("Icinga API password:")

    # write config to file
    with open(args.config, "w+") as fd:
        config.write(fd)
        fd.flush()
        fd.close()

    return config


def execute(args):
    """Execute specified command as subprocess and enfore timeout if necessary"""

    try:
        # execute check_command
        result = subprocess.run(
            args.check_command, timeout=args.timeout, capture_output=True, text=True
        )

        # sanity check return value
        if not 0 <= result.returncode <= 3:
            return SimpleNamespace(
                returncode=3,
                stdout=f"check_command returned with unexpected return code {result.returncode}.",
            )

        return result

    except subprocess.TimeoutExpired:
        return SimpleNamespace(
            returncode=3, stdout="check_command timed out.", stderr=None
        )


def deliver(args, config, result) -> bool:
    """build api request and deliver passive result"""

    data = {}
    default = config["DEFAULT"]

    # return status for icinga
    data["exit_status"] = result.returncode

    # split check_command output and feed into plugin_output and optional performance_data
    output = result.stdout.strip().split("|")
    data["plugin_output"] = (
        output[0] if len(output) > 0 else "check_command had no output."
    )
    if len(output) > 1:
        data["performance_data"] = output[1]

    # pass check_command and check_source
    data["check_command"] = result.args
    data["check_source"] = default["check_source"]

    # pass ttl if provided
    if args.ttl:
        data["ttl"] = args.ttl

    # set filter
    data["type"] = "Service"
    data["filter"] = (
        f"host.name==\"{default['check_source']}\" && service.name==\"{args.s}\""
    )

    # create encoded credentials
    credentials = f"{default['user']}:{default['password']}"
    encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

    # headers
    headers = {
        "Accept": "application/json",
        "X-HTTP-Method-Override": "POST",
        "Authorization": f"Basic {encoded_credentials}",
    }

    # build request
    request = Request(
        default["url"],
        data=bytes(json.dumps(data), encoding="utf-8"),
        headers=headers,
        method="post",
    )

    # load acccepted certificate from file and use for verification of the connection
    ctx = ssl.create_default_context(cafile=args.cacert)

    # execute request
    try:
        response = urlopen(request, context=ctx)
        if 200 <= response.status <= 299:
            return
        raise Exception(
            f"API endpoint returned non-success status code {response.status}: {response.read().decode('utf-8')}"
        )
    except HTTPError as e:
        res = e.read().decode("utf-8")
        if e.status == 500:
            if json.loads(res) == {"results": []}:
                raise Exception(
                    f"API endpoint returned 500 status code, this is most likely due to trying to submit to a sattelite instead of the active master: {res}"
                )
            else:
                raise Exception(f"API endpoint returned 500: {res}")
        elif e.status == 404:
            raise Exception(
                "API endpoint returned 404, this is probably due to your filters not matching (hostname or service name)."
            )
    except ssl.SSLError as e:
        if "certificate verify failed" in str(e):
            raise Exception(
                "API endpoint returned an untrusted certificate, please delete the config and re-run the script."
            )


def main():

    # parse command line arguments
    args = parse_args()

    # load or create config file
    config = load_config(args)

    # execute check_command
    result = execute(args)

    # deliver results to api
    deliver(args, config, result)


if __name__ == "__main__":
    main()
