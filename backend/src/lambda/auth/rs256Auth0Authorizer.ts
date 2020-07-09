
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJCFG7oscde9+3MA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi0tOHctZXJydi51cy5hdXRoMC5jb20wHhcNMjAwNzA4MTkwOTQxWhcN
MzQwMzE3MTkwOTQxWjAkMSIwIAYDVQQDExlkZXYtLTh3LWVycnYudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA52OUUCDvlOc8YDeV
qv7fTfDqEtyq679fEYT5dCLU1s4sBDBKsmPXWGV+iuwtb10/q6P/Wlh2gSgBXOQ8
jr9KqC2YVnbO6VV9W1GhX+OJCuwVSntKhqa1q09g0Ku+o17tr9NrNkEbrUJ8Dafa
o/xz6sNtAXrchwZ8OGW40pTRKDAmO3h3S8s99h7xjG13rwt8GV3mQ6RqxTwbv36p
uZaB1FPkt9Udh04OX59RK68eqzp2BUHwnwGzqj2nLyS8WP5I8FMDRQU3HKHhlHBu
DAth5ojy9z8WTi19eio11G/oNPPCaoRsyl56zNLVRBgspkM0aOrVWi0JGxjhPd42
qfzdAwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSTZFFvSQbX
z9WRz3iOxgNGtsXDxjAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
ADPPoJYauuRCLAYMWStnHMk0559/+VdCmY5phG5W6fN/OluPd4Y0r08LnnSoVGAg
2undQ4OkQ4q5ooynnoMIb8jZgPkqYgWAmt77LcFSD4fmWMYFn4D9TSbaORv4tt/V
eH0llj0ihwn+3RBiF4VI3wdWjDYjmqw5JwNbggCnpZXeNCCavjSdoqGGIgl/p2a2
76LWoRDHJiAvh+dOpaH88psaZ5rUoeXt6fqkoBayeAhcWvPg8BiIvJflQ5UQBRGn
KN+nCUFBWac8JKFkgmSdlMZrriCFU3cIER2K7M7wnG39usNoEx8oMNot/fVUXLAB
11/zUD+XV/BK2od5GgPeMYk=
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}
