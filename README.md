# pbkdf2-opgp-key [![Join the chat at https://gitter.im/ZenyWay/pbkdf2-opgp-key](https://badges.gitter.im/ZenyWay/pbkdf2-opgp-key.svg)](https://gitter.im/ZenyWay/pbkdf2-opgp-key?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![NPM](https://nodei.co/npm/pbkdf2-opgp-key.png?compact=true)](https://nodei.co/npm/pbkdf2-opgp-key/)
[![build status](https://travis-ci.org/ZenyWay/pbkdf2-opgp-key.svg?branch=master)](https://travis-ci.org/ZenyWay/pbkdf2-opgp-key)
[![coverage status](https://coveralls.io/repos/github/ZenyWay/pbkdf2-opgp-key/badge.svg?branch=master)](https://coveralls.io/github/ZenyWay/pbkdf2-opgp-key)
[![Dependency Status](https://gemnasium.com/badges/github.com/ZenyWay/pbkdf2-opgp-key.svg)](https://gemnasium.com/github.com/ZenyWay/pbkdf2-opgp-key)

[opgp-service](https://www.npmjs.com/package/opgp-service) keys encrypted
with a [pbkdf2-sha512](https://www.npmjs.com/package/pbkdf2sha512) digest.

Pbkdf2OpgpKey instances encapsulate a _private_ OpgpProxyKey.

# <a name="example"></a> example
```ts
import getPbkdf2OpgpKeyFactory from 'pbkdf2-opgp-key'
import getOpgpService, { OpgpService, OpgpProxyKey } from 'opgp-service'
import debug = require('debug')
debug.enable('example:*')

const opgp = getOpgpService()
const getPbkdf2OpgpKey = getPbkdf2OpgpKeyFactory(opgp, {
  // keysize: 2048, locked: false (defaults)
  pbkdf2: {
    salt: 32, // generate random 32-byte long string, encoding: base64 (default)
    iterations: 16384, // min 8192, default 65536
    length: 64 // min 32, max 64, default 64
    // digest is always 'sha512'
  }
})

debug('example:')('generate key...')

const key = getPbkdf2OpgpKey({
	user: 'j.doe@example.com',
  passphrase: 'secret passphrase'
})
.then(debug('example:key:'))
// { key: OpgpProxyKey, pbkdf2: { salt: "...", ... }, unlock: Function }
```
the files of this example are available [in this repository](./spec/example).

view a [live version of this example in your browser console](https://cdn.rawgit.com/ZenyWay/pbkdf2-opgp-key/v1.0.0/spec/example/index.html),
or by cloning this repository and running the following commands from a terminal:
```bash
npm install
npm run example
```

# <a name="api"></a> API v1.1 stable
`ES5` and [`Typescript`](http://www.typescriptlang.org/) compatible.
coded in `Typescript 2`, transpiled to `ES5`.

secure Pbkdf2OpgpKey instances can either be randomly generated,
or imported from an armored representation.
the corresponding factory is instantiated with the exported builder.

Pbkdf2OpgpKey instances currently expose a single method:
`unlock  (passphrase: string): Promise<Pbkdf2OpgpKeyClass>`

browse the API's [public type declarations](./src/index.ts#L22-L69).

for a detailed specification of the API,
[run the unit tests in your browser](https://cdn.rawgit.com/ZenyWay/pbkdf2-opgp-key/v1.0.0/spec/web/index.html).

# <a name="contributing"></a> CONTRIBUTING
see the [contribution guidelines](./CONTRIBUTING.md)

# <a name="license"></a> LICENSE
Copyright 2017 Stéphane M. Catala

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the [License](./LICENSE) for the specific language governing permissions and
Limitations under the License.
