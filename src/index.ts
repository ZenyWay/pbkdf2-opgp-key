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
import { isString, isFunction } from './utils'
import {
  Pbkdf2Sha512Factory, Pbkdf2Sha512Config, Pbkdf2sha512Digest, Pbkdf2sha512DigestSpec
} from 'pbkdf2sha512'
import { OpgpService, OpgpProxyKey } from 'opgp-service'
import { __assign as assign } from 'tslib'

export interface Pbdkf2OpgpKeyFactoryBuilder {
  (opgp: OpgpService, config?: Partial<Pbdkf2OpgpKeyConfig>): Pbdkf2OpgpKeyFactory
}

export interface Pbdkf2OpgpKeyConfig {
  /**
   * default key size.
   * default: 2048
   */
  size: number
  /**
   * lock returned key when `true`.
   * otherwise unlock.
   * default: false
   */
  locked: boolean
  /**
   * default Pbkdf2 parameters.
   */
  pbkdf2: Partial<Pbkdf2Sha512Config>
  /**
   * pbkdf2 function factory.
   * default: default export from `pbkdf2sha512` module
   */
  getkdf: Pbkdf2Sha512Factory
}

export interface Pbdkf2OpgpKeyFactory {
  (creds: Credentials): Promise<Pbkdf2OpgpKey>
}

export interface Credentials {
  user: string
  passphrase: string
}

export interface Pbkdf2OpgpKey {
  key: OpgpProxyKey
  pbkdf2: Pbkdf2sha512DigestSpec
  unlock (passphrase: string): Promise<Pbkdf2OpgpKey>
}

const KEY_SIZE_DEFAULT = 2048

const getPbkdf2OpgpKeyFactory: Pbdkf2OpgpKeyFactoryBuilder =
function (opgp: OpgpService, config?: Partial<Pbdkf2OpgpKeyConfig>) {
  if (!isValidOpgpService(opgp)) { throw new TypeError('invalid argument') }

  const spec = assign({}, { size: KEY_SIZE_DEFAULT }, config)
  const getPbkdf2 = isFunction(spec.getkdf) ? spec.getkdf : require('pbkdf2sha512').default
  const pbkdf2Spec = assign({}, spec.pbkdf2)
  const keysize = spec.size
  const unlocked = !spec.locked

  return function getPbkdf2OpgpKey (creds: Credentials) {
    return isValidCredentials(creds)
    ? Pbkdf2OpgpKeyClass.getInstance(opgp, getPbkdf2, pbkdf2Spec, keysize, unlocked, creds)
    : Promise.reject<Pbkdf2OpgpKey>(new TypeError('invalid argument'))
  }
}

class Pbkdf2OpgpKeyClass implements Pbkdf2OpgpKey {
  static getInstance (opgp: OpgpService, getPbkdf2: Pbkdf2Sha512Factory,
  pbkdf2spec: Pbkdf2Sha512Config, keysize: number, unlocked: boolean, creds: Credentials):
  Promise<Pbkdf2OpgpKey> {
    const pbkdf2 = getPbkdf2(pbkdf2spec)
    const key = pbkdf2(creds.passphrase)
    .then(({ value, spec }) => Promise.resolve<OpgpProxyKey>(opgp.generateKey(creds.user, {
        passphrase: value,
        size: keysize,
        unlocked: unlocked
      }))
      .then(key => new Pbkdf2OpgpKeyClass(getPbkdf2, opgp, key, spec)))
    return Pbkdf2OpgpKeyClass.wrapInstance(key)
  }

  unlock (passphrase: string): Promise<Pbkdf2OpgpKeyClass> {
    const pbkdf2 = this.getPbkdf2(this.pbkdf2)
    return pbkdf2(passphrase)
    .then(digest => Promise.resolve<OpgpProxyKey>(this.opgp.unlock(this.key, digest.value)))
    .then(key => new Pbkdf2OpgpKeyClass(this.getPbkdf2, this.opgp, key, this.pbkdf2))
  }

  /**
   * revealing module pattern.
   * hide private properties required for unlock.
   */
  private static wrapInstance (key: Promise<Pbkdf2OpgpKeyClass>): Promise<Pbkdf2OpgpKey> {
    return key.then(key => ({
      key: key.key,
      pbkdf2: key.pbkdf2,
      unlock (passphrase: string): Promise<Pbkdf2OpgpKey> {
        return isString(passphrase)
        ? Pbkdf2OpgpKeyClass.wrapInstance(key.unlock(passphrase))
        : Promise.reject(new TypeError('invalid argument'))
      }
    }))
  }

  private constructor (
    public getPbkdf2: Pbkdf2Sha512Factory,
    public opgp: OpgpService,
    public key: OpgpProxyKey,
    public pbkdf2: Pbkdf2sha512DigestSpec
  ) {}
}

function isValidOpgpService (val: any): val is OpgpService {
  return !!val && [ 'generateKey', 'unlock' ].every(prop => isFunction(val[prop]))
}

function isValidCredentials (val: any): val is Credentials {
  return !!val && isString(val.user) && isString(val.passphrase)
}

export default getPbkdf2OpgpKeyFactory
