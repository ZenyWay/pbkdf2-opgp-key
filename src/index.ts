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
import { isString, isNumber, isFunction } from './utils'
import {
  Pbkdf2Sha512Factory, Pbkdf2Sha512Config, Pbkdf2sha512DigestSpec, Pbkdf2sha512Digest
} from 'pbkdf2sha512'
import { OpgpService, OpgpProxyKey, Eventual, OneOrMore } from 'opgp-service'
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
   *
   * note that regardless of this setting,
   * when importing a key from an armored string
   * it is always unlocked during the process
   * to validate the passphrase.
   *
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

export { Pbkdf2Sha512Factory, Pbkdf2Sha512Config, Pbkdf2sha512DigestSpec }

export interface Pbdkf2OpgpKeyFactory {
  /**
   * generate a new random Pbkdf2OpgpKey
   */
  (creds: Eventual<Credentials>): Promise<Pbkdf2OpgpKey>
  (user: Eventual<string>, passphrase: Eventual<string>): Promise<Pbkdf2OpgpKey>
  /**
   * import a Pbkdf2OpgpKey from a PGP armor with pbkdf2 parameters.
   * note that the passphrase is mandatory to validate
   * the pbkdf2 parameters.
   * the returned key is unlocked.
   */
  (armor: Eventual<Pbkdf2OpgpKeyArmor>, passphrase: Eventual<string>): Promise<Pbkdf2OpgpKey>
}

export interface Credentials {
  user: string
  passphrase: string
}

export interface Pbkdf2OpgpKey {
  key: OpgpProxyKey
  pbkdf2: Pbkdf2sha512DigestSpec
  unlock (passphrase: string): Promise<Pbkdf2OpgpKey>
  toArmor (): Promise<Pbkdf2OpgpKeyArmor>
  /**
   * @return {Promise<Pbkdf2OpgpKey>} locked
   */
  clone (): Promise<Pbkdf2OpgpKey>
}

export interface Pbkdf2OpgpKeyArmor {
  armor: string
  pbkdf2: Pbkdf2sha512DigestSpec
}

interface Pbkdf2sha512DigestFactory {
  (password: Buffer|Uint8Array|string): Promise<Pbkdf2sha512Digest>
}

const KEY_SIZE_DEFAULT = 2048

const getPbkdf2OpgpKeyFactory: Pbdkf2OpgpKeyFactoryBuilder =
function (opgp: OpgpService, config?: Partial<Pbdkf2OpgpKeyConfig>) {
  if (!isValidOpgpService(opgp)) { throw new TypeError('invalid argument') }

  const keyspec: Pbdkf2OpgpKeyConfig = assign({}, { size: KEY_SIZE_DEFAULT }, config)
  keyspec.pbkdf2 = assign({}, keyspec.pbkdf2)
  keyspec.getkdf = isFunction(keyspec.getkdf)
  ? keyspec.getkdf
  : require('pbkdf2sha512').default

  function getKey (spec: Eventual<Credentials|Pbkdf2OpgpKeyArmor|string>,
  passphrase?: Eventual<string>) {
    const opgpkey =
    Promise.all<Credentials|Pbkdf2OpgpKeyArmor|string, string>([ spec, passphrase ])
    .then(([ spec, passphrase ]) => getPbkdf2OpgpKey(opgp, keyspec, spec, passphrase))

    return wrapInstance(opgpkey)
  }

  return getKey
}

function getPbkdf2OpgpKey (opgp: OpgpService, config: Pbdkf2OpgpKeyConfig,
spec: Credentials|Pbkdf2OpgpKeyArmor|string, passphrase?: string): Promise<Pbkdf2OpgpKey> {
  if (isString(spec)) {
    return getPbkdf2OpgpKey(opgp, config, { user: spec, passphrase: passphrase })
  }
  if (isValidCredentials(spec)) {
    return Pbkdf2OpgpKeyClass.newInstance(opgp, config, spec.user, spec.passphrase)
  }
  if (isValidKeyArmor(spec) && isString(passphrase)) {
    return Pbkdf2OpgpKeyClass.fromPbkdf2KeyArmor(opgp, config, spec, passphrase)
  }
  return Promise.reject<Pbkdf2OpgpKey>(new TypeError('invalid arguments'))
}

/**
 * revealing module pattern.
 * hide private properties required for unlock.
 */
function wrapInstance (key: Promise<Pbkdf2OpgpKeyClass>): Promise<Pbkdf2OpgpKey> {
  return key.then(key => ({
    key: key.key,
    pbkdf2: key.pbkdf2,
    unlock (passphrase: string) { return wrapInstance(key.unlock(passphrase)) },
    toArmor () { return key.toArmor() },
    clone () { return wrapInstance(key.clone()) }
  }))
}

class Pbkdf2OpgpKeyClass implements Pbkdf2OpgpKey {
  static newInstance (opgp: OpgpService, keyspec: Pbdkf2OpgpKeyConfig,
  user: string, passphrase: string): Promise<Pbkdf2OpgpKeyClass> {
    const pbkdf2 = keyspec.getkdf(keyspec.pbkdf2)

    return pbkdf2(passphrase)
    .then(digest => Promise.resolve<OpgpProxyKey>(opgp.generateKey(user, {
        passphrase: digest.value,
        size: keyspec.size,
        unlocked: !keyspec.locked
      }))
      .then(key => new Pbkdf2OpgpKeyClass(keyspec.getkdf, opgp, key, digest.spec)))
  }

  static fromPbkdf2KeyArmor (opgp: OpgpService, keyspec: Pbdkf2OpgpKeyConfig,
  armor: Pbkdf2OpgpKeyArmor, passphrase: string): Promise<Pbkdf2OpgpKeyClass> {
    const pbkdf2 = keyspec.getkdf(assign({}, keyspec.pbkdf2, armor.pbkdf2))
    const key = opgp.getKeysFromArmor(armor.armor)
    .then(key => Array.isArray(key)
    ? Promise.reject<OpgpProxyKey>(new Error('unsupported multiple key armor')) // unlikely
    : key)

    return Promise.all<OpgpProxyKey,Pbkdf2sha512Digest>([ key, pbkdf2(passphrase) ])
    .then<Pbkdf2OpgpKeyClass>(([ key, digest ]) => opgp.unlock(key, digest.value)
    .then(key => new Pbkdf2OpgpKeyClass(keyspec.getkdf, opgp, key, digest.spec)))
  }

  unlock (passphrase: string): Promise<Pbkdf2OpgpKeyClass> {
    if (!isString(passphrase)) {
      return Promise.reject(new TypeError('invalid argument'))
    }
    const pbkdf2 = this.getPbkdf2(this.pbkdf2)
    return pbkdf2(passphrase)
    .then(digest => Promise.resolve<OpgpProxyKey>(this.opgp.unlock(this.key, digest.value)))
    .then(key => new Pbkdf2OpgpKeyClass(this.getPbkdf2, this.opgp, key, this.pbkdf2))
  }

  toArmor (): Promise<Pbkdf2OpgpKeyArmor> {
    return Promise.resolve<string>(this.opgp.getArmorFromKey(this.key))
    .then(armor => ({
      armor: armor,
      pbkdf2: assign({}, this.pbkdf2)
    }))
  }

  clone (): Promise<Pbkdf2OpgpKeyClass> {
    return Promise.resolve<string>(this.opgp.getArmorFromKey(this.key))
    .then<OpgpProxyKey>(armor => this.opgp.getKeysFromArmor(armor)) // only one key
    .then(key => new Pbkdf2OpgpKeyClass(this.getPbkdf2, this.opgp, key, this.pbkdf2))
  }

  private constructor (
    public getPbkdf2: Pbkdf2Sha512Factory,
    public opgp: OpgpService,
    public key: OpgpProxyKey,
    public pbkdf2: Pbkdf2sha512DigestSpec
  ) {}
}

const OPGP_SERVICE_METHODS = [
  'generateKey', 'getKeysFromArmor', 'getArmorFromKey', 'unlock'
]

function isValidOpgpService (val: any): val is OpgpService {
  return !!val && OPGP_SERVICE_METHODS.every(prop => isFunction(val[prop]))
}

function isValidCredentials (val: any): val is Credentials {
  return !!val && isString(val.user) && isString(val.passphrase)
}

function isValidKeyArmor (val: any): val is Pbkdf2OpgpKeyArmor {
  return !!val && isString(val.armor) && !!val.pbkdf2 && isString(val.pbkdf2.salt)
}

export default getPbkdf2OpgpKeyFactory
