'use strict';

// Starbase Cryptic is required
// https://github.com/StarbaseAlpha/Starbase
// https://github.com/StarbaseAlpha/Cryptic

function Cynops(cryptic) {

  if (!cryptic) {
    throw("An instance of Starbase Cryptic is require.");
  }

  async function createUser() {
    let idk = await cryptic.createECDH();
    let spk = await cryptic.createECDH();
    let card = await createCard({idk, spk});
    let opks = {};
    let user = {
      idk,
      spk,
      opks,
      card
    };
    return cloneState(user);
  }

  async function updateSPK(user) {
    let spk = await cryptic.createECDH();
    return spk;
  }

  async function createCard(user) {
    let card = {
      "idk":user.idk.pub,
      "spk":user.spk.pub,
    };
    return cloneState(card);
  }

  async function sessionHash(combinedDH, init) {
   let hashed = await cryptic.hkdf(combinedDH, new Uint8Array(32), cryptic.fromText('SIGNAL'), 256 * 3);
    let sharedKey = cryptic.decode(hashed).slice(0,32);
    let authKey = cryptic.decode(hashed).slice(32,64);
    let sessionId = cryptic.decode(hashed).slice(64, 96);
    let ad = cryptic.combine(cryptic.decode(init.from),cryptic.decode(init.to));
    let AD = await cryptic.hkdf(cryptic.combine(authKey, ad), new Uint8Array(32), cryptic.fromText("AD"), 256);
    return {"sessionId":cryptic.encode(sessionId), "sk":cryptic.encode(sharedKey), AD, init};
  }

  async function createSession(user, card) {
    let epk = await cryptic.createECDH();
    let init = {};
    init.to = card.idk;
    init.from = user.idk.pub.toString();
    init.spk = card.spk;
    init.epk = epk.pub;
    if (card.opk) {
      init.opk = card.opk;
    }
    let dh1 = await cryptic.ecdh(user.idk.key, init.spk);
    let dh2 = await cryptic.ecdh(epk.key, init.to);
    let dh3 = await cryptic.ecdh(epk.key, init.spk);
    let dh4 = null;
    if (init.opk) {
      dh4 = await cryptic.ecdh(epk.key, init.opk);
    }
    let combinedDH = await cryptic.combine(cryptic.combine(dh1, dh2), cryptic.combine(dh3, dh4));
    return sessionHash(combinedDH, init);
  }

  async function openSession(user, init) {
    let dh1 = await cryptic.ecdh(user.spk.key, init.from);
    let dh2 = await cryptic.ecdh(user.idk.key, init.epk);
    let dh3 = await cryptic.ecdh(user.spk.key, init.epk);
    let dh4 = null;
    if (init.opk && user.opks[init.opk]) {
      let opk = user.opks[init.opk].toString();
      delete user.opks[init.opk];
      dh4 = await cryptic.ecdh(opk, init.epk);
    }
    let combinedDH = await cryptic.combine(cryptic.combine(dh1, dh2), cryptic.combine(dh3, dh4));
    return sessionHash(combinedDH, init);
  }

  async function rootKDF(rk, dh) {
    let ratchet = await cryptic.hkdf(cryptic.decode(dh), cryptic.decode(rk), cryptic.fromText('ROOT'), 512);
    let RK = cryptic.encode(cryptic.decode(ratchet).slice(0, 32));
    let CK = cryptic.encode(cryptic.decode(ratchet).slice(32));
    return [RK, CK];
  }

  async function chainKDF(ck) {
    let mk = await cryptic.hmacSign(cryptic.decode(ck), "\x01");
    let CK = await cryptic.hmacSign(cryptic.decode(ck), "\x02");
    return [CK, mk];
  }

  async function createInitRatchet(session) {
    let state = {};
    state.DHs = await cryptic.createECDH();
    state.DHr = session.init.spk;
    let dh = await cryptic.ecdh(state.DHs.key, state.DHr);
    [state.RK, state.CKs] = await rootKDF(session.sk, dh);
    state.CKr = null;
    state.Ns = 0;
    state.Nr = 0;
    state.PN = 0;
    state.MKSKIPPED = {};
    return state;
  }

  async function openInitRatchet(session, spk) {
    let state = {};
    state.DHs = spk;
    state.DHr = null;
    state.RK = session.sk;
    state.CKs = null;
    state.CKr = null;
    state.Ns = 0;
    state.Nr = 0;
    state.PN = 0;
    state.MKSKIPPED = {};
    return state;
  }

  async function trySkippedMessageKeys(state, header, ciphertext, AEAD) {
    if (state.MKSKIPPED[header.dh] && state.MKSKIPPED[header.dh][header.n]) {
      let mk = state.MKSKIPPED[header.dh][header.n];
      let KEY = await cryptic.hkdf(cryptic.combine(cryptic.decode(mk), cryptic.fromText(JSON.stringify(header))), new Uint8Array(32), cryptic.fromText("ENCRYPT"), 256);
      let plaintext = await cryptic.decrypt(ciphertext, cryptic.decode(KEY), cryptic.decode(AEAD)).catch(err => {
        return null;
      });
      if (plaintext) {
        delete state.MKSKIPPED[header.dh][header.n];
        return {"header":header, "plaintext":plaintext};
      } else {
        return null;
      }
    }
  }

  async function skipMessageKeys(state, until, maxSkip) {
    if (state.Nr + maxSkip < until) {
      return Promise.reject({
        "message": "Too many skipped messages!"
      });
    }
    if (state.CKr) {
      while (state.Nr < until) {
        let mk = null;
        [state.CKr, mk] = await chainKDF(state.CKr);
        if (!state.MKSKIPPED[state.DHr]) {
          state.MKSKIPPED[state.DHr] = {};
        }
        state.MKSKIPPED[state.DHr][state.Nr] = mk;
        state.Nr += 1;
      }
    }
  }

  async function DHRatchet(state, header) {
    state.PN = state.Ns;
    state.Ns = 0;
    state.Nr = 0;
    state.DHr = header.dh;
    let dh1 = await cryptic.ecdh(state.DHs.key, state.DHr);
    [state.RK, state.CKr] = await rootKDF(state.RK, dh1);
    state.DHs = await cryptic.createECDH();
    let dh2 = await cryptic.ecdh(state.DHs.key, state.DHr);
    [state.RK, state.CKs] = await rootKDF(state.RK, dh2);
    return true;
  }

  async function ratchetEncrypt(state, msg, AD, init) {
    let mk = null;
    [state.CKs, mk] = await chainKDF(state.CKs, state);
    let header = {
      "dh": state.DHs.pub,
      "pn": state.PN,
      "n": state.Ns
    };
    state.Ns += 1;
    let AEAD = await cryptic.hkdf(cryptic.combine(cryptic.decode(AD), cryptic.fromText(JSON.stringify(header))), new Uint8Array(32), cryptic.fromText("AEAD"), 256);
    let KEY = await cryptic.hkdf(cryptic.combine(cryptic.decode(mk), cryptic.fromText(JSON.stringify(header))), new Uint8Array(32), cryptic.fromText("ENCRYPT"), 256);
    let encrypted = {
      header,
      "ciphertext": await cryptic.encrypt(JSON.stringify(msg), cryptic.decode(KEY), cryptic.decode(AEAD))
    };
    if (init) {
      encrypted.init = cloneState(init);
    }
    return encrypted;
  }

  async function ratchetDecrypt(state, msgPayload = {}, AD, maxSkip = 10) {
    let {
      header,
      ciphertext
    } = msgPayload;
    let AEAD = await cryptic.hkdf(cryptic.combine(cryptic.decode(AD), cryptic.fromText(JSON.stringify(header))), new Uint8Array(32), cryptic.fromText("AEAD"), 256);
    let found = await trySkippedMessageKeys(state, header, ciphertext, AEAD || null);
    if (found) {
      return found;
    }
    if (header.dh !== state.DHr) {
      await skipMessageKeys(state, header.pn, maxSkip);
      await DHRatchet(state, header);
    }
    await skipMessageKeys(state, header.n, maxSkip);
    let mk = null;
    [state.CKr, mk] = await chainKDF(state.CKr);
    state.Nr += 1;
    let KEY = await cryptic.hkdf(cryptic.combine(cryptic.decode(mk), cryptic.fromText(JSON.stringify(header))), new Uint8Array(32), cryptic.fromText("ENCRYPT"), 256);
    let plaintext = await cryptic.decrypt(ciphertext, cryptic.decode(KEY), cryptic.decode(AEAD)).catch(err => {
      throw ({
        "error": "failed to decrypt"
      });
    });
    delete state.init;
    return {
      header,
      "plaintext":JSON.parse(plaintext)
    };
  }

  function cloneState(src) {
    let target = {};
    if (typeof src === 'string') {
      target = src.toString();
      return target;
    }
    if (src instanceof Array) {
      target = [];
    }
    for (let prop in src) {
      if (src[prop] && typeof src[prop] === 'object') {
        target[prop] = cloneState(src[prop]);
      } else {
        target[prop] = src[prop];
      }
    }
    return target;
  }

  async function sealEnvelope(userIDK, to, message) {
    let idk = userIDK.pub;
    let env = {};
    let epk = await cryptic.createECDH();

    let dh1 = await cryptic.ecdh(epk.key, to);
    let envSalt = cryptic.combine(cryptic.decode(to), cryptic.decode(epk.pub));
    let envBits = await cryptic.hkdf(cryptic.decode(dh1), envSalt, cryptic.fromText("ENVELOPE"), 256 * 3);
    let envAD = cryptic.combine(cryptic.decode(envBits).slice(0, 32), cryptic.combine(cryptic.decode(epk.pub), cryptic.decode(to)));
    let envKey = cryptic.decode(envBits).slice(32, 64);
    let envChain = cryptic.decode(envBits).slice(64, 96);

    let sealed = await cryptic.encrypt(idk, envKey, envAD);

    let dh2 = await cryptic.ecdh(userIDK.key, to)
    let sealSalt = cryptic.combine(envChain, cryptic.fromText(sealed));
    let sealBits = await cryptic.hkdf(cryptic.decode(dh2), cryptic.combine(sealSalt, cryptic.decode(idk)), cryptic.fromText("SEAL"), 256 * 2);
    let sealAD = cryptic.combine(cryptic.decode(sealBits).slice(0, 32), cryptic.decode(to));
    let sealKey = cryptic.decode(sealBits).slice(32, 64); 

    env.to = to;
    env.epk = epk.pub;
    env.seal = sealed;

    env.ciphertext = await cryptic.encrypt(JSON.stringify(message), sealKey, sealAD);
    return env;
  }

  async function openEnvelope(userIDK, env) {
    let idk = userIDK.pub;
    let epk = env.epk;

    let dh1 = await cryptic.ecdh(userIDK.key, epk);
    let envSalt = cryptic.combine(cryptic.decode(idk), cryptic.decode(epk));
    let envBits = await cryptic.hkdf(cryptic.decode(dh1), envSalt, cryptic.fromText("ENVELOPE"), 256 * 3);
    let envAD = cryptic.combine(cryptic.decode(envBits).slice(0, 32), cryptic.combine(cryptic.decode(epk), cryptic.decode(idk)));
    let envKey = cryptic.decode(envBits).slice(32, 64);
    let envChain = cryptic.decode(envBits).slice(64, 96);

    let from = await cryptic.decrypt(env.seal, envKey, envAD);

    let dh2 = await cryptic.ecdh(userIDK.key, from);
    let sealSalt = cryptic.combine(envChain, cryptic.fromText(env.seal));
    let sealBits = await cryptic.hkdf(cryptic.decode(dh2), cryptic.combine(sealSalt, cryptic.decode(from)), cryptic.fromText("SEAL"), 256 * 2);
    let sealAD = cryptic.combine(cryptic.decode(sealBits).slice(0, 32), cryptic.decode(idk));
    let sealKey = cryptic.decode(sealBits).slice(32, 64);

    let contents = await cryptic.decrypt(env.ciphertext, sealKey, sealAD);
    return {"from": from, "contents": JSON.parse(contents)};
  }

  function Session(sessionData) {
    let sessionState = cloneState(sessionData);
    let session = {};

    session.to = () => {
      return cloneState(sessionData).user;
    };

    session.send = async (message) => {
      let state = cloneState(sessionState.state);
      let payload = await ratchetEncrypt(state, message, sessionState.AD||null, sessionState.init||null);
      payload.to = sessionData.user.toString();
      sessionState.state = cloneState(state);
      return payload;
    };

    session.read = async (payload) => {
      let state = cloneState(sessionState.state);
      let decrypted = await ratchetDecrypt(state, payload, sessionState.AD||null);
      if (sessionState.init) {
        delete sessionState.init;
      }
      let msg = {"header": payload.header, "plaintext":decrypted.plaintext, "from": session.to()};
      sessionState.state = cloneState(state);
      return msg;
    };

    session.save = () => {
      let backup = {
        "state":cloneState(sessionState.state)
      };
      if (sessionState.sessionId) {
        backup.sessionId = cloneState(sessionState.sessionId);
      }
      if (sessionState.init) {
        backup.init = cloneState(sessionState.init);
      }
      if (sessionState.user) {
        backup.user = cloneState(sessionState.user);
      }
      if (sessionState.AD) {
        backup.AD = cloneState(sessionState.AD);
      }
      return backup;
    };

    return session;

  }

  function User(userData) {

    let userState = cloneState(userData);
    let user = {};

    let useUser = () => {
      return userState;
    };

    user.getCard = async (includeOPK=false) => {
      let card = cloneState(userState.card);
      if (includeOPK) {
        let opk = await cryptic.createECDH();
        userState.opks[opk.pub] = opk.key;
        card.opk = opk.pub.toString();
      }
      return card;
    };

    user.updateSPK = async () => {
      let spk = await updateSPK(userState);
      userState.spk = spk;
      userState.card = await createCard(userState);
      return true;
    };

    user.sealEnvelope = async (to, msg) => {
      return sealEnvelope(useUser().idk, to, msg);
    };

    user.openEnvelope = async (env) => {
      return openEnvelope(useUser().idk, env);    
    };

    user.createSession = async (card) => {
      let session = await createSession(useUser(), card);
      session.user = card.idk;
      session.state = await createInitRatchet(session);
      delete session.sk;
      return Session(session);
    };

    user.openSession = async (init) => {
      let session = await openSession(useUser(), init);
      session.user = init.from;
      session.recvFrom = useUser().idk.pub.toString();
      session.state = await openInitRatchet(session, useUser().spk);
      delete session.sk;
      return Session(session);
    };

    user.loadSession = async (session) => {
      return Session(session);
    };

    user.save = () => {
      return cloneState(userState);
    };

    return user;
  }

  let cynops = {};

  cynops.createUser = async () => {
    let userData = await createUser();
    return User(userData);
  };

  cynops.loadUser = async (userData) => {
    return User(userData);
  };

  return cynops;

}

// if is node module
if (typeof module !== 'undefined' && module && module.exports) {
  module.exports = Cynops;
}
