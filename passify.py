#!/usr/bin/env python3

import ssl
import sys
import json
import socket
import base64
import pathlib
import os.path
import argparse
import subprocess
import configparser
from getpass import getpass
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
    except Exception as e:
        return None

def parse_args():
    """Parse command line arguments, capture known and unknown args"""
    
    parser = argparse.ArgumentParser(description=__doc__)
    configpath = pathlib.Path(__file__).parent.resolve() / "config.ini"
    parser.add_argument("--config", type=pathlib.Path, default=configpath, help="Path where to store/load config from. [default=config.ini]")
    parser.add_argument("--timeout", type=int, default=None, help="Optional timeout for execution in seconds.")
    parser.add_argument("-s", type=str, required=True, metavar="SERVICE NAME", help="Specify service name")
    parser.add_argument("--ttl", type=int, default=None, help="TTL argument to pass to icinga api")
    parser.add_argument("check_command", nargs=argparse.REMAINDER, help="Check_command to execute with arguments.")
    
    return parser.parse_args()
    
def load_config(args):
    """Load config from file, init with necessary values"""
    
    config = configparser.ConfigParser()
    default = config["DEFAULT"]
    
    # load config from file
    if os.path.isfile(args.config):
        config.read(args.config)
        if not {"url", "user", "password", "check_source"}.issubset(default):
            raise Exception("Invalid configuration file.")
        
        return config
    
    # request api url until a valid url is provided
    durl = "https://localhost:5665"
    while not "url" in default or url := verify_url(default["url"]) is None:
        if url is None:
            print("[ERROR] Invalid url, please specify a valid url.")
        default["url"] = input(f"Icinga API master url (default: {durl}):") or durl
        default["url"] += "/v1/actions/process-check-result"
    
    # TODO: Add download certificate and validate connection
    
    # request check_source property
    hostname = socket.getfqdn()
    default["check_source"] = input(f"Input host name (default:{hostname}):") or hostname
    
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
            args.check_command,
            timeout=args.timeout,
            capture_output=True,
            text=True
        )
        
        # sanity check return value
        if not 0 <= result.returncode <= 3:
            return SimpleNamespace(returncode=3, stdout=f"check_command returned with unexpected return code {result.returncode}.")
        
        return result
        
    except subprocess.TimeoutExpired:
        return SimpleNamespace(returncode=3, stdout="check_command timed out.", stderr=None)
    
def deliver(args, config, result) -> bool:
    """build api request and deliver passive result"""
    
    data = {}
    default = config["DEFAULT"]
    
    # return status for icinga
    data["exit_status"] = result.returncode
    
    # split check_command output and feed into plugin_output and optional performance_data
    output = result.stdout.strip().split("|")
    data["plugin_output"] = output[0] if len(output) > 0 else "check_command had no output."
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
    data["filter"] = f"host.name==\"{default['check_source']}\" && service.name==\"{args.s}\""
    
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
        method="post"
    )
    
    # FIXME: ignore ssl context
    ctx = ssl._create_unverified_context()
    
    # execute request
    try:
        response = urlopen(request, context=ctx)
        if 200 <= response.status <= 299:
            return
        raise Exception(f"API endpoint returned non-success status code {response.status}: {response.read().decode('utf-8')}")
    except HTTPError as e:
        res = e.read().decode("utf-8")
        if e.status == 500:
            if json.loads(res) == {"results": []}:
                raise Exception(f"API endpoint returned 500 status code, this is most likely due to trying to submit to a sattelite instead of the active master: {res}")
            else:
                raise Exception(f"API endpoint returned 500: {res}")
        elif e.status == 404:
            raise Exception("API endpoint returned 404, this is probably due to your filters not matching (hostname or service name).")

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
