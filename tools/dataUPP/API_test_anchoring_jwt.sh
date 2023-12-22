HARDWARE_ID='<ENTER-UUID-HERE>'
JWT='<ENTER-TOKEN-HERE>'
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