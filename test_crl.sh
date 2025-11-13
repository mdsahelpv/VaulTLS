#!/bin/bash
echo "Testing VaulTLS CRL functionality..."

# Wait for services to start
sleep 10

# Test CRL endpoint
echo "Testing CRL endpoint..."
curl -s -o /tmp/crl_test http://localhost:8000/api/certificates/crl

if [ -f /tmp/crl_test ] && [ -s /tmp/crl_test ]; then
    echo "✅ CRL endpoint returned data ($(stat -c%s /tmp/crl_test) bytes)"
    echo "CRL content preview:"
    head -c 100 /tmp/crl_test | od -c
else
    echo "❌ CRL endpoint failed or returned empty response"
    exit 1
fi

echo "🎉 CRL functionality test completed successfully!"
