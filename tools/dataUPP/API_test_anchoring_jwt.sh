HARDWARE_ID='98880181-4770-44da-85a9-da86a6ccaa1f'
JWT='<ENTER-TOKEN-HER>'
UPP='standard_upp.bin'
RESPONSE_UPP='response_upp.bin'

curl -X POST "https://niomon.prod.ubirch.com/" \
--header "X-Ubirch-Auth-Type: ubirch-token" \
--header "X-Ubirch-Hardware-Id: $HARDWARE_ID" \
--header "X-Ubirch-Credential: $JWT" \
--header "Content-Type: application/octet-stream" \
--data-binary @$UPP \
--output $RESPONSE_UPP \
--verbose