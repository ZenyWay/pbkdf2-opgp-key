/*
 * Copyright 2017 Stephane M. Catala
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * Limitations under the License.
 */
;
import getPbkdf2OpgpKeyFactory from '../../src'
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
debugger
const key = getPbkdf2OpgpKey({
	user: 'j.doe@example.com',
  passphrase: 'secret passphrase'
})
.then(debug('example:key:'))
// { key: OpgpProxyKey, pbkdf2: { salt: "...", ... }, unlock: Function }
