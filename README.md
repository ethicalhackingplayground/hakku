# hakku
Hakku is a android take over tool using various deployment options.

## Install
> python install.py

## SMS Deployment option
you need to go to the twilio website and create an account
and fill in the information in the configuration file.
https://www.twilio.com/ but it basically sends someone a malicious
link through SMS.

## EvilTWin AP Deployment option
This deployment option is still in the testing phase, but what it does
is creates an evil ap (access point) that serves a malicious update browser page
and when someone downloads the update and installs it, you will have access to their phone.

## Bluetooth Deployment option
This will scan & send a malicious backdoor through bluetooth and it also spams the request
so they are forced to download the backdoor.

## Facebook Messenger Deployment option
This will send someone a malcious link through to FB Messenger and when they click on it, it
will either download a backdoor to there phone.
