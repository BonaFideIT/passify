# passify

An icinga check_command wrapper to icinga api for submitting passive check results.
Call any nagios/icinga compatible check executable to submit results as a passive result.

## usage

`usage: passify.py [-h] [--config CONFIG] [--timeout TIMEOUT] -s SERVICE NAME [--ttl TTL] ...`

Deploy passify.py on your server, this can be done locally or in your path. Call it with

`python3 passify.py -s "Example Service" check_example <check_arguments>`

or give it execution rights and call it like this:

`./passify.py -s "Example Service" check_example <check_arguments>`

Or in path like this:

`passify -s "Example Service" check_example <check_arguments>`

# installation

`pip install icinga-passify`

* copy passify.py to your server.
* Install to path for full convenience if you like, call as seen above:

`ln -s /usr/local/bin/passify /location/to/passify.py`

* Upon first run, you will be asked several configuration questions:

  * the icinga master url **submissions are only possible through the currently active master**
  * verify the fingerprint (hint: `openssl x509 -in /var/lib/icinga2/certs/<hostname>.crt -noout -fingerprint -sha256`)
  * username and password for api submission (only basic-auth is currently supported)

* alternatively you can deploy a config file (default: config.ini) with the script:

```
[DEFAULT]
url = https://localhost:5665/v1/actions/process-check-result
check_source = example.com
user = <api_user>
password = <api_password>

[TLS]
fingerprint = d163f22c2021a498926ff8c30da0288ac20d1b9edaa80d1dbb14c0aebf85245b
```

