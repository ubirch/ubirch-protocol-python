HARDWARE_ID='<ENTER-UUID-HERE>'

curl -X 'GET' "https://identity.prod.ubirch.com/api/keyService/v1/pubkey/current/hardwareId/$HARDWARE_ID" \
--header 'accept: application/json' \
--output public-key.json \
--verbose