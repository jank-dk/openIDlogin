
# Tool to log on a user on an OpenID Connect identity provider

## Usage of openIDlogin

### Main arguments:
| Argument          | Description                                              |
| :---              | :---                                                     |
| -help             | Shows help                                               |
| -disablecertcheck | Disable TLS certificate checks                           |
| -rooturl          | The root URL of the OpenID Connect provider. Used to retrieve authorization and token endpoints using .well-knownopenid-configuration | 
| -authurl          | The authorization URL. Not necessary if retrieved using -rooturl |
| -tokenurl         | The token URL. Not necessary if retrieved using -rooturl |
| -clientid         | The client ID                                            |
| -clientsecret     | The client secret                                        |
| -listenport       | Port to listen on for the code. Default is 12345         |
| -scope            | Scopes to request. Default is "openid profile email"     |

You will have to register `http://localhost:<listenport>` as a redirect URL on the identity provider