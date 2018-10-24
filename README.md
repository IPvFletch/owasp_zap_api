# owasp_zap_api
Python script to configure and run OWASP ZAP. Includes JWT token-based and cookie-based authorization and is designed 
to work with modern web-based apps utilizing a (single-page) JavaScript front-end and a RESTful API backend.

## Setup
Set the following ENV vars for authentication to your app:

* `API_USER`
* `API_PASS`

Modify the script to point to the proper `API_HOSTNAME` and `ADMIN_HOSTNAME` hosts.

Modify `AUTH_TOKEN` on line 41 to match the JSON key coming back in the sign-in response.


## Running OWASP ZAP
Docker is an easy way to run OWASP ZAP:

    $ docker run \
     --name owasp-zap \
     -d \
     -p 8080:8080 \
     -u zap \
     owasp/zap2docker-weekly \
     zap-x.sh \
     -daemon \
     -host 0.0.0.0 \
     -port 8080 \
     -config api.addrs.addr.name=.* \
     -config api.addrs.addr.regex=true \
     -config api.key=1234567890
    
    $ docker logs -f owasp-zap

You can verify it's working by using the OWASP ZAP Application UI.

Then run this script:

    $ export API_USER="admin@site.com"
    $ export API_PASS="*******"

    $ ./owasp_zap_api.py

It will run through and scan the various URLs, then produce a report when it is done.

