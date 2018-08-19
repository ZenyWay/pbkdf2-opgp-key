/**
 * Copyright 2018 Stephane M. Catala
 * @author Stephane M. Catala
 * @license Apache@2.0
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
//
import getPbkdf2OpgpKeyFactory from '../../src'
import getOpgpService from 'opgp-service'
import log from './console'

const opgp = getOpgpService()
const getPbkdf2OpgpKey = getPbkdf2OpgpKeyFactory(opgp, {
  // keysize: 2048, locked: false (defaults)
  pbkdf2: {
    salt: 32, // generate random 32-byte long string, encoding: base64 (default)
    iterations: 8192, // min 8192, default 65536
    length: 64 // min 32, max 64, default 64
    // digest is always 'sha512'
  }
})

log('example:')('generate key...')
const key = getPbkdf2OpgpKey('j.doe@example.com', 'secret passphrase')
key.then(log('example:key:'))
// { key: OpgpProxyKey, pbkdf2: { salt: "...", ... }, unlock: Function, toArmor: Function, clone: Function }

const armor = key.then(key => key.toArmor())
armor.then(log('example:armor:'))
// { armor: "-----BEGIN PGP PRIVATE KEY BLOCK----- ...", pbkdf2: { salt: "...", ... } }

armor.then(armor => getPbkdf2OpgpKey(armor, 'secret passphrase'))
.then(log('example:from-armor:'))
// { key: OpgpProxyKey, pbkdf2: { salt: "...", ... }, unlock: Function, toArmor: Function, clone: Function }
