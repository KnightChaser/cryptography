# KnightChaser's RSA-Based digital signature implementation written in PowerShell

Add-Type -AssemblyName System.Security

# Generate a RSA key pair
function GenerateRSAKeyPair {
    param (
        [int] $keyLengthInBits
    )

    # Powershell provides a built-in cmdlet to generate RSA key pair
    $rsaProvider = New-Object System.Security.Cryptography.RSACryptoServiceProvider($keyLengthInBits)
    $privateKey = $rsaProvider.ToXmlString($true)
    $publicKey = $rsaProvider.ToXmlString($false)

    return $privateKey, $publicKey
}

# Sign a message with a RSA private key
function SignMessageWithRSA {
    param (
        [byte[]] $message,
        [string] $privateKeyXml
    )

    $rsaProvider = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsaProvider.FromXmlString($privateKeyXml)

    $sha256 = New-Object System.Security.Cryptography.SHA256Managed
    $hashedMessage = $sha256.ComputeHash($message)
    Write-Host "[Sender]   Hashed Message (SHA256) : 0x$([System.BitConverter]::ToString($hashedMessage).Replace('-', ''))"

    # Provide RSA private key, hashed message and hash algorithm to sign the message to create a digital signature
    $signature = $rsaProvider.SignHash($hashedMessage, 'SHA256')

    return $signature
}

# Verify a message with a RSA public key
function VerifyMessageWithRSA {
    param (
        [byte[]] $message,
        [byte[]] $signature,
        [string] $publicKeyXml
    )

    $rsaProvider = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsaProvider.FromXmlString($publicKeyXml)

    $sha256 = New-Object System.Security.Cryptography.SHA256Managed
    $hashedMessage = $sha256.ComputeHash($message)
    Write-Host "[Receiver] Hashed Message (SHA256) : 0x$([System.BitConverter]::ToString($hashedMessage).Replace('-', ''))"

    # Provide RSA public key, hashed message and hash algorithm to verify the digital signature from the sender
    [bool] $isSignatureValid = $rsaProvider.VerifyHash($hashedMessage, 'SHA256', $signature)

    return $isSignatureValid
}

# Generate RSA key pair
$keyLengthInBits = 2048
$privateKeyXml, $publicKeyXml = GenerateRSAKeyPair -keyLengthInBits $keyLengthInBits

# Message to be signed
$message = [System.Text.Encoding]::UTF8.GetBytes("OwO Digital Signature (with RSA)!")

$decodedMessage = [System.Text.Encoding]::UTF8.GetString($message)
Write-Host "[Sender] Message         : $decodedMessage"
Write-Host "[Sender] Message (bytes) : $($message | ForEach-Object { $_.ToString("X2") })"

[xml]$privateKeyXmlObject = $privateKeyXml
Write-Host "[Private Key] Modulus    : $($privateKeyXmlObject.RSAKeyValue.Modulus)"     # Modulus is the product of two prime numbers
Write-Host "[Private Key] Exponent   : $($privateKeyXmlObject.RSAKeyValue.Exponent)"    # Exponent is the public key
Write-Host "[Private Key] P          : $($privateKeyXmlObject.RSAKeyValue.P)"           # P and Q are the prime factors
Write-Host "[Private Key] Q          : $($privateKeyXmlObject.RSAKeyValue.Q)"
Write-Host "[Private Key] DP         : $($privateKeyXmlObject.RSAKeyValue.DP)"          # DP and DQ are the private key's prime factors
Write-Host "[Private Key] DQ         : $($privateKeyXmlObject.RSAKeyValue.DQ)"
Write-Host "[Private Key] InverseQ   : $($privateKeyXmlObject.RSAKeyValue.InverseQ)"    # InverseQ is the Chinese Remainder Theorem coefficient
Write-Host "[Private Key] D          : $($privateKeyXmlObject.RSAKeyValue.D)"           # D is the known as the private exponent

[xml]$publicKeyXmlObject = $publicKeyXml
Write-Host "[Public Key]  Modulus    : $($publicKeyXmlObject.RSAKeyValue.Modulus)"      # Modulus is the product of two prime numbers
Write-Host "[Public Key]  Exponent   : $($publicKeyXmlObject.RSAKeyValue.Exponent)"

# Sign the message with the private key
$signature = SignMessageWithRSA -message $message -privateKeyXml $privateKeyXml

# Digital signature doesn't encrypt the message, it just signs it.
# To provide confidentiality, the message must be encrypted with a symmetric key. (e.g. digital envelope)

# Verify the signature with the public key
if (VerifyMessageWithRSA -message $message -signature $signature -publicKeyXml $publicKeyXml) {
    Write-Host "** Signature is valid because the hash values are the same. **"
} else {
    Write-Host "** Signature is invalid because the hash values are different. **"
}

# Example Output
# [Sender] Message         : OwO Digital Signature (with RSA)!
# [Sender] Message (bytes) : 79 119 79 32 68 105 103 105 116 97 108 32 83 105 103 110 97 116 117 114 101 32 40 119 105 116 104 32 82 83 65 41 33
# [Private Key] Modulus    : tHc05Q9eznuYgylhzsz0fhrO1uuGNMBPB3oKWl68/jvC9bTEXwI9ZrTgocieW9ww71yI6CW3hg6c+Uao+/hgum4IG36LBKDlAd65myR1CS9DjF5WkAZDHsYS3x9QV7meKDHAjo+gHNGvwZkf2hXBamzKXpZ3EIjV01nJL4IkQ9oTz+iegldYwcEmez+JNf0v3iOlQ/+kaK1VP71PLMIXVjyMy4OJyfuWu+wod6F+zvikz3Ip1qLwfrdTbO10/3SlvVfo2CKd/Jb12xWf2CLl3kx3Y7wh2jLaC4zysC7AU7Suxx6m18uaJVNjqexg8P033jEgaG3EVS4JQlm5CIYcQQ==
# [Private Key] Exponent   : AQAB
# [Private Key] P          : 5QBRwgH3JFs59UA044HkVnRMFrHFDYaGHdIChM2z3HdFQcQmNIocKZziA8w3Rqp9MJoAqGI7O14iXpwlreyhIOJfAq5PUeu1qOYLOqLl+4aqxgBQHX6eMdyMPBX8VXY12ivmNXuahVaKa2nqM7MR1+P750QATUNIJGb1MCE9G5s=
# [Private Key] Q          : yb3+SLoAqW3FWdpvxS2d82/EyLkWryKa7ZmOCiqXW9Z4omDoaejwxUSRhQs5EWGkUlSPcH5fB6Rw6DhtkZmRFNjK99H/GGmg0gjJnwulSFb29iWbyJ/wMETG9Tz9wl68+4TdHUSHZd9X6/USJF4UkG+HyTp/X9tafs0QOxU7i1M=
# [Private Key] DP         : cJWDnHoS4xDmoah7WA6YD9kFP3MOiePFNAv3qQrojk8lAXxJvDLaPasfgvZ3hopzGd3czOveawWQqCrka2mWnfAs/chsvr2/hdXzV1SW9N30P3wP5zBE3gar+y5j7DA9sZE7kLe/9CXjz4M23UwATb+MLNrFuzaE1UC48nyk6lk=
# [Private Key] DQ         : Ux0rPdsjmqnWvIX5tkps4HYTpH5ckhq3qVux4Q5a/UMGwB8coUWOrDbrnNxazoZjpGeiEL5/eC6PNZzJx0p1Mxl9xUuGxQ//aYilSBkMJxls9UvZOnZqBfjP3wkZopJVWWoLjptFDPtOxa9ZohIAduD8GDM5dsxwI/1nym+c8HE=
# [Private Key] InverseQ   : av+o52mxHsnyyiSCuIyVWl9JCMEyKOFLA/dx1eX25WNInvvrLoRQe1F2DmQe/M5g4PNahoX6q0Qf7RqkxMWRhpA5/TTTraclofY2L1rlT2JMaBIMGv3WX9k6dE8EzbsBArK/PySbFnZ5fQjViqf7Y7KB4eNWcfe7Qa6Bm7I2cJQ=
# [Private Key] D          : r1ae+us7Jw1o+g7r69ywtBFh4+lEJN6wKkiF5JXltHHmE4qFvPXVKIQXOLlOO1wt43KZxkxXCpYKKBxiNSZ2/MvJbsU9Vsroli+LUFRUrg7Q54IFQrwC3NSAI28uRX2gT9c/CoQ7gaStykD3dJHssXVwDgTNPDBm6Il08obUq2KFmFoRQg00Xksf8smn2qFv7s/skPPUyAQK+25bdN4GBx/gxpIU0grg5WCLXz5CNc6GKRQcfJ+jx1jTL/d9uwo0/7kWuRkA8sCwbfjlUCX2jgVUFVPLpZ2/sMBawi9WgonfXVxw0OjZgeTpl6muRaVVUpz+fmAJB8La7pM0ZSEUXQ==
# [Public Key]  Modulus    : tHc05Q9eznuYgylhzsz0fhrO1uuGNMBPB3oKWl68/jvC9bTEXwI9ZrTgocieW9ww71yI6CW3hg6c+Uao+/hgum4IG36LBKDlAd65myR1CS9DjF5WkAZDHsYS3x9QV7meKDHAjo+gHNGvwZkf2hXBamzKXpZ3EIjV01nJL4IkQ9oTz+iegldYwcEmez+JNf0v3iOlQ/+kaK1VP71PLMIXVjyMy4OJyfuWu+wod6F+zvikz3Ip1qLwfrdTbO10/3SlvVfo2CKd/Jb12xWf2CLl3kx3Y7wh2jLaC4zysC7AU7Suxx6m18uaJVNjqexg8P033jEgaG3EVS4JQlm5CIYcQQ==
# [Public Key]  Exponent   : AQAB
# [Sender]   Hashed Message (SHA256) : 0x435B089B2D9C70181921046DCD6D3A557CCE4B67FCD529275ABF4811B9FCCF40
# [Receiver] Hashed Message (SHA256) : 0x435B089B2D9C70181921046DCD6D3A557CCE4B67FCD529275ABF4811B9FCCF40
# ** Signature is valid because the hash values are the same. **