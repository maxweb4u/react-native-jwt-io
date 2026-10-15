# react-native-jwt-io
This package generates JWT tokens using jsrsasign library.

> **1.0.4 is a security update.** It moves `jsrsasign` from 8.x, which carries
> critical advisories, to 11.x. Upgrade with `npm install react-native-jwt-io@^1.0.4`;
> no code changes are needed.
>
> **2.0.0 is in development**: a TypeScript rewrite with claim validation
> (`exp`, `nbf`, `iss`, `aud`), more algorithms, and a new API. After it is
> published, the 1.0.x line receives security fixes for three months and is then
> deprecated. See [CHANGELOG.md](CHANGELOG.md).


## Installation

npm install react-native-jwt-io --save

## How to use

import jwt from 'react-native-jwt-io';

....

var token = jwt.encode({id: 'user_id'}, 'your_secret_key');

## License

MIT