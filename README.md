# JWKS-Server

![Screenshot 2025-02-04 162542](https://github.com/user-attachments/assets/f539ab45-b391-41bc-af86-b09fa4d1180e)

## How to build:

"go build"

## How to run:

"go run ." or "./Ianj751.exe"

## How to Test:

- go test -v
  ### To test coverage
      - go test -v -coverprofile cover
      - go tool cover -html="cover"

## Routes

#### For Expired JWT

    localhost:8080/auth?expired=true

#### For Unexpired JWT

    localhost:8080/auth
    localhost:8080/auth?expired="<anything-other-than-true>"

#### For JWKS

    localhost:8080/.well-known/jwks.json

## Format of Responses

#### Expired JWT

    {
        "expiry": 1234,
        "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBNYW1hIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    }

#### Unexpired JWT

    {
        "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBNYW1hIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    }

#### JWKS

    {
    "keys": [
        {
            "alg": "RS256",
            "kty": "RSA",
            "n": "2irN_ouSCsfXaN3LuXTpdlrGnnDZEdcHCIuOLkDz_QOJm5fB6ijS_WBxHP8nokRxP4KBWY_HcvZZtCN19McztD2fXxnUtyXjLsZ6zCZEkH2a83ulzEgM7dSbPD43Y20M-6RkRRSGHwtGH4x7SnvH4RY4ieSHYpKOKpcGoqB9mg7B2nupNW1ni0vTdlJ512ikn1XLnw6SRzwokHx4lZFce27buqWlhaUrl9ITC1ytGIyEjMLG4uFxTHwfxxBCWXodeHpbUZ9_Ae5mOlN25T7cYIMF3IQgYBLCHnAKLVB2jewi6b6FnZcgfkD4kU5NjY8tuKwY9UC7CCXl9UVoLSl46w",
            "e": "AQAB",
            "kid": "1",
            "exp": "2025-01-30T14:56:05.9572448-06:00"
        }
    ]
    }
