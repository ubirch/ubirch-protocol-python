HARDWARE_ID='98880181-4770-44da-85a9-da86a6ccaa1f'

curl -X 'GET' "https://identity.prod.ubirch.com/api/keyService/v1/pubkey/current/hardwareId/$HARDWARE_ID" \
--header 'accept: application/json' \
--output public-key.json \
--verbose