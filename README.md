# react-native-jwt-io
This package generates JWT tokens using jsrsasign library.


## Installation

npm install react-native-jwt-io --save

## How to use

import jwt from 'react-native-jwt-io';

....

var token = jwt.encode({id: 'user_id'}, 'your_secret_key');

## License

MIT