CREDENTIAL='Bearer <ENTER-TOKEN-HERE>'
DATA='<ENTER-BASE64-ENCODED-HASH-HERE>'

curl -X POST "https://verify.prod.ubirch.com/api/v2/upp" \
--header "Authorization: $CREDENTIAL" \
--data "$DATA" \
--output response.json \
--verbose