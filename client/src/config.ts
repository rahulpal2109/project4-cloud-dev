// TODO: Once your application is deployed, copy an API id here so that the frontend could interact with it
const apiId = 'jgre2j9haa'
export const apiEndpoint = `https://${apiId}.execute-api.ap-south-1.amazonaws.com/dev`

export const authConfig = {
  // TODO: Create an Auth0 application and copy values from it into this map
  domain: 'dev--8w-errv.us.auth0.com',            // Auth0 domain
  clientId: 'sds4BXsTwxtxWDbUgPMi1GUkd4u4yeG5',          // Auth0 client id
  callbackUrl: 'http://localhost:3000/callback'
}
