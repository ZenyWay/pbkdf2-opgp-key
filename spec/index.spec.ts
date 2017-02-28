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
const getPbkdf2OpgpKeyFactory = require('../src').default

let mock: {
  getkdf: jasmine.Spy
  pbkdf2: jasmine.Spy
  opgp: {
    generateKey: jasmine.Spy
    getKeysFromArmor: jasmine.Spy
    getArmorFromKey: jasmine.Spy
    unlock: jasmine.Spy
  }
}
let getPbkdf2: jasmine.Spy
let opgpkey: any
let digest: any
let creds: {
  user: string
  passphrase: string
}

beforeEach(() => {
  opgpkey = {
    handle: 'key-handle'
  }
  digest = {
    value: 'digest',
    spec: {}
  }
  const pbkdf2 = jasmine.createSpy('pbkdf2')
  .and.returnValue(Promise.resolve(digest))
  const getkdf = jasmine.createSpy('getkdf')
  .and.returnValue(pbkdf2)
  const generateKey = jasmine.createSpy('generateKey')
  .and.returnValue(Promise.resolve(opgpkey))
  const getKeysFromArmor = jasmine.createSpy('getKeysFromArmor')
  const getArmorFromKey = jasmine.createSpy('getArmorFromKey')
  const unlock = jasmine.createSpy('unlock')
  mock = {
    getkdf: getkdf,
    pbkdf2: pbkdf2,
    opgp: {
      generateKey: generateKey,
      getKeysFromArmor: getKeysFromArmor,
      getArmorFromKey: getArmorFromKey,
      unlock: unlock
    }
  }
  creds = {
    user: 'j.doe@test.org',
    passphrase: 'secret passphrase'
  }
})

describe('getPbkdf2OpgpKeyFactory (opgp: OpgpService, config?: Partial<Pbdkf2OpgpKeyConfig>): ' +
'Pbdkf2OpgpKeyFactory', () => {
  it('returns a function', () => {
    expect(getPbkdf2OpgpKeyFactory(mock.opgp)).toEqual(jasmine.any(Function))
  })

  describe('when called with an OpgpService instance', () => {
    beforeEach((done) => {
      const getPbkdf2OpgpKey = getPbkdf2OpgpKeyFactory(mock.opgp, { getkdf: mock.getkdf })
      getPbkdf2OpgpKey(creds)
      .then((key: any) => key.unlock(creds.passphrase))
      .then(() => setTimeout(done))
      .catch((err: any) => setTimeout(() => done.fail(err)))
    })
    it('configures the returned function with that instance and default settings',
    () => {
      expect(mock.opgp.generateKey).toHaveBeenCalled()
      expect(mock.opgp.unlock).toHaveBeenCalled()
      expect(mock.getkdf).toHaveBeenCalledWith({})
      expect(mock.opgp.generateKey).toHaveBeenCalledWith(creds.user,
      jasmine.objectContaining({
        passphrase: digest.value,
        size: 2048,
        unlocked: true
      }))
    })
  })

  describe('when called with an OpgpService instance ' +
  'and a Pbdkf2OpgpKeyConfig instance { size?: number, locked?: boolean, ' +
  'pbkdf2?: Partial<Pbkdf2Sha512Config> }',
  () => {
    let config: any
    beforeEach((done) => {
      config = {
        size: 4096,
        locked: true,
        pbkdf2: {},
        getkdf: mock.getkdf
      }
      const getPbkdf2OpgpKey = getPbkdf2OpgpKeyFactory(mock.opgp, config)
      getPbkdf2OpgpKey(creds)
      .then(() => setTimeout(done))
      .catch((err: any) => setTimeout(() => done.fail(err)))
    })
    it('configures the returned function accordingly', () => {
      expect(mock.getkdf).toHaveBeenCalledWith(config.pbkdf2)
      expect(mock.opgp.generateKey).toHaveBeenCalledWith(creds.user,
      jasmine.objectContaining({
        passphrase: digest.value,
        size: config.size,
        unlocked: !config.locked
      }))
    })
  })

  describe('when called with anything else than a valid OpgpService instance',
  () => {
    let args: any
    let getKeyFactory: any
    beforeEach(() => {
      args = [
        null, undefined, true, 42, 'foo', () => { return 'foo' }, [ 'foo' ],
        { foo: 'bar' }
      ]
      getKeyFactory = (arg: any) => () => getPbkdf2OpgpKeyFactory(arg, { getkdf: mock.getkdf })
    })
    it('throws an "invalid argument" TypeError', () => {
      args.every((arg: any) =>
        expect(getKeyFactory(arg)).toThrowError(TypeError, 'invalid argument'))
      expect(mock.opgp.generateKey).not.toHaveBeenCalled()
      expect(mock.opgp.unlock).not.toHaveBeenCalled()
      expect(mock.getkdf).not.toHaveBeenCalled()
      expect(mock.opgp.generateKey).not.toHaveBeenCalled()
    })
  })
})

describe('getPbkdf2OpgpKey (creds: Credentials): Promise<Pbkdf2OpgpKey>', () => {
  let getPbkdf2OpgpKey: any
  beforeEach(() => {
    getPbkdf2OpgpKey = getPbkdf2OpgpKeyFactory(mock.opgp, { getkdf: mock.getkdf })
  })

  describe('when called with a Credentials object: { user: string, passphrase: string }',
  () => {
    let key: any
    beforeEach((done) => {
      getPbkdf2OpgpKey(creds)
      .then((_key: any) => key = _key)
      .then(() => setTimeout(done))
      .catch((err: any) => setTimeout(() => done.fail(err)))
    })
    it('returns a Pbkdf2OpgpKey object:  { key: OpgpProxyKey, ' +
    'pbkdf2: Pbkdf2Sha512Config, unlock: (passphrase: string) => Promise<Pbkdf2OpgpKey>',
    () => {
      expect(key).toEqual({
        key: opgpkey,
        pbkdf2: digest.spec,
        unlock: jasmine.any(Function),
        toArmor: jasmine.any(Function),
        clone: jasmine.any(Function)
      })
    })
  })

  describe('when called with anything else', () => {
    let args: any
    let errors: any
    beforeEach((done) => {
      args = [
        null, undefined, true, 42, 'foo', () => { return 'foo' }, [ 'foo' ],
        { user: 42, passphrase: 'passphrase'}, { user: 'j.doe@test.org', passphrase: 42 }
      ]
      Promise.all(args.map((arg: any) => getPbkdf2OpgpKey(arg).catch((err: any) => err)))
      .then((errs: any) => errors = errs)
      .then(() => setTimeout(done))
      .catch((err: any) => setTimeout(() => done.fail(err)))
    })
    it('rejects with an "invalid credentials" TypeError', () => {
      expect(errors.length).toBe(args.length)
      errors.every((error: any) => expect(error).toEqual(jasmine.any(TypeError))
      && expect(error.message).toBe('invalid credentials'))
    })
  })
})

describe('getPbkdf2OpgpKey (armor: { armor: string, pbkdf2: Pbkdf2sha512DigestSpec }, ' +
'passphrase: string): Promise<Pbkdf2OpgpKey>', () => {
  let getPbkdf2OpgpKey: any
  beforeEach(() => {
    getPbkdf2OpgpKey = getPbkdf2OpgpKeyFactory(mock.opgp, { getkdf: mock.getkdf })
  })

  describe('when called with the specified arguments', () => {
    let key: any
    let armor: any
    beforeEach((done) => {
      mock.opgp.getKeysFromArmor.and.returnValue(Promise.resolve(opgpkey))
      mock.opgp.unlock.and.returnValue(Promise.resolve(opgpkey))
      armor = {
        armor: 'armor',
        pbkdf2: {
          salt: 'salt'
        }
      }
      getPbkdf2OpgpKey(armor, creds.passphrase)
      .then((_key: any) => key = _key)
      .then(() => setTimeout(done))
      .catch((err: any) => setTimeout(() => done.fail(err)))
    })
    it('returns a Pbkdf2OpgpKey object encapsulating the extracted key: ' +
    '{ key: OpgpProxyKey, pbkdf2: Pbkdf2Sha512Config, ' +
    'unlock: (passphrase: string) => Promise<Pbkdf2OpgpKey>',
    () => {
      expect(key).toEqual({
        key: opgpkey,
        pbkdf2: digest.spec,
        unlock: jasmine.any(Function),
        toArmor: jasmine.any(Function),
        clone: jasmine.any(Function)
      })
      expect(mock.opgp.getKeysFromArmor).toHaveBeenCalledWith('armor')
      expect(mock.pbkdf2).toHaveBeenCalledWith(creds.passphrase)
      expect(mock.opgp.unlock).toHaveBeenCalledWith(opgpkey, digest.value)
    })
  })

  describe('when called with an armored string representation of multiple private keys',
  () => {
    let error: any
    beforeEach((done) => {
      mock.opgp.getKeysFromArmor.and.returnValue(Promise.resolve([ opgpkey, opgpkey ]))

      getPbkdf2OpgpKey({ armor: 'armor', pbkdf2: { salt: 'salt' } }, creds.passphrase)
      .then((res: any) => setTimeout(() => done.fail(new Error(res))))
      .catch((err: any) => error = err)
      .then(() => setTimeout(done))
    })
    it('rejects with an "unsupported multiple key armor" Error', () => {
      expect(error).toEqual(jasmine.any(Error))
      expect(error.message).toBe('unsupported multiple key armor')
      expect(mock.opgp.getKeysFromArmor).toHaveBeenCalledWith('armor')
    })
  })

  describe('when called with an incorrect passphrase string', () => {
    let error: any
    beforeEach((done) => {
      mock.opgp.getKeysFromArmor.and.returnValue(Promise.resolve(opgpkey))
      mock.opgp.unlock.and.returnValue(Promise.reject(new TypeError('boom')))
      getPbkdf2OpgpKey({ armor: 'armor', pbkdf2: { salt: 'salt' } }, creds.passphrase)
      .then((err: any) => setTimeout(() => done.fail(new Error(err))))
      .catch((err: any) => error = err)
      .then(() => setTimeout(done))
    })
    it('rejects with the error thrown by the underlying OpgpService#unlock method',
    () => {
      expect(error).toEqual(jasmine.any(Error))
      expect(error.message).toBe('boom')
      expect(mock.opgp.getKeysFromArmor).toHaveBeenCalledWith('armor')
      expect(mock.pbkdf2).toHaveBeenCalledWith(creds.passphrase)
      expect(mock.opgp.unlock).toHaveBeenCalledWith(opgpkey, digest.value)
    })
  })

  describe('when called with anything else', () => {
    let args: any
    let errors: any
    beforeEach((done) => {
      args = [
        null, undefined, true, 42, () => { return 'foo' }, [ 'foo' ],
        { foo: 'bar' }
      ]
      const results = args.map((arg: any) => getPbkdf2OpgpKey(arg, 'armor'))
      .concat(args.map((arg: any) => getPbkdf2OpgpKey('passphrase', arg)))

      Promise.all(results.map((result: any) => result.catch((err: any) => err)))
      .then((errs: any) => errors = errs)
      .then(() => setTimeout(done))
      .catch((err: any) => setTimeout(() => done.fail(err)))
    })
    it('rejects with an "invalid argument" TypeError', () => {
      expect(errors.length).toBe(2 * args.length)
      errors.every((error: any) => expect(error).toEqual(jasmine.any(TypeError))
      && expect(error.message).toBe('invalid argument'))
    })
  })
})

describe ('Pbkdf2OpgpKey', () => {
  let key: any
  beforeEach((done) => {
    const getPbkdf2OpgpKey = getPbkdf2OpgpKeyFactory(mock.opgp, { getkdf: mock.getkdf })
    getPbkdf2OpgpKey(creds)
    .then((_key: any) => key = _key)
    .then(() => setTimeout(done))
    .catch((err: any) => setTimeout(() => done.fail(err)))
  })

  describe('unlock (passphrase: string): Promise<Pbkdf2OpgpKey>', () => {
    describe('when called with the correct passphrase string', () => {
      let unlocked: any
      beforeEach((done) => {
        mock.opgp.unlock.and.returnValue(Promise.resolve(opgpkey))
        key.unlock(creds.passphrase)
        .then((key: any) => unlocked = key)
        .then(() => setTimeout(done))
        .catch((err: any) => setTimeout(() => done.fail(err)))
      })
      it('returns an unlocked instance of the key', () => {
        expect(mock.opgp.unlock).toHaveBeenCalledWith(opgpkey, digest.value)
        expect(unlocked).toEqual({
          key: opgpkey,
          pbkdf2: digest.spec,
          unlock: jasmine.any(Function),
          toArmor: jasmine.any(Function),
          clone: jasmine.any(Function)
        })
      })
    })

    describe('when called with any other string than the correct passphrase', () => {
      let error: any
      beforeEach((done) => {
        mock.opgp.unlock.and.returnValue(Promise.reject(new TypeError('boom')))
        key.unlock(creds.passphrase)
        .catch((err: any) => error = err)
        .then(() => setTimeout(done))
        .catch((err: any) => setTimeout(() => done.fail(err)))
      })
      it('rejects with the error thrown by the underlying OpgpService#unlock method',
      () => {
        expect(error).toEqual(jasmine.any(TypeError))
        expect(error.message).toBe('boom')
      })
    })

    describe('when called with anything else than a string', () => {
      let args: any
      let errors: any
      beforeEach((done) => {
        args = [
          null, undefined, true, 42, () => { return 'foo' }, [ 'foo' ],
          { foo: 'bar' }
        ]
        Promise.all(args.map((arg: any) => key.unlock(arg).catch((err: any) => err)))
        .then((errs: any) => errors = errs)
        .then(() => setTimeout(done))
        .catch((err: any) => setTimeout(() => done.fail(err)))
      })
      it('rejects with an "invalid argument" TypeError', () => {
        expect(errors.length).toBe(args.length)
        expect(mock.opgp.unlock).not.toHaveBeenCalled()
        errors.every((error: any) => expect(error).toEqual(jasmine.any(TypeError))
        && expect(error.message).toBe('invalid argument'))

      })
    })
  })

  describe('toArmor (): Promise<string>', () => {
    let armor: any
    beforeEach((done) => {
      mock.opgp.getArmorFromKey.and.returnValue(Promise.resolve('armor'))
      key.toArmor()
      .then((_armor: any) => armor = _armor)
      .then(() => setTimeout(done))
      .catch((err: any) => setTimeout(() => done.fail(err)))
    })

    it('returns the armored string representation of the key', () => {
      expect(mock.opgp.getArmorFromKey).toHaveBeenCalledWith(opgpkey)
      expect(armor).toEqual({
        armor: 'armor',
        pbkdf2: digest.spec
      })
    })
  })

  describe('clone (): Promise<string>', () => {
    let clone: any
    beforeEach((done) => {
      mock.opgp.getArmorFromKey.and.returnValue(Promise.resolve('armor'))
      mock.opgp.getKeysFromArmor.and.returnValue(Promise.resolve(opgpkey))
      key.clone()
      .then((_clone: any) => clone = _clone)
      .then(() => setTimeout(done))
      .catch((err: any) => setTimeout(() => done.fail(err)))
    })

    it('returns a locked clone of the key', () => {
      expect(mock.opgp.getArmorFromKey).toHaveBeenCalledWith(opgpkey)
      expect(mock.opgp.getKeysFromArmor).toHaveBeenCalledWith('armor')
      expect(mock.opgp.unlock).not.toHaveBeenCalled()
      expect(clone).toEqual({
        key: opgpkey,
        pbkdf2: digest.spec,
        unlock: jasmine.any(Function),
        toArmor: jasmine.any(Function),
        clone: jasmine.any(Function)
      })
    })
  })
})
