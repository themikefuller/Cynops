'use strict';

async function Test(cynops) {

  let alice = await cynops.createUser();
  let bob = await cynops.createUser();

  let bobCard = await bob.getCard(true);

  let sessionA = await alice.createSession(bobCard);

  let msgA0 = await sessionA.send("Hey, Bob! Its me, Alice!");

  let sealA0 = await alice.sealEnvelope(msgA0.to, msgA0);

  let msgA1 = await sessionA.send("Me again! You get this?");

  let sealA1 = await alice.sealEnvelope(msgA1.to, msgA1);

  let openA1 = await bob.openEnvelope(sealA1);
  let sessionB = await bob.openSession(openA1.contents.init);
  let readA1 = await sessionB.read(openA1.contents);

  let openA0 = await bob.openEnvelope(sealA0);
  let readA0 = await sessionB.read(openA0.contents);

  let msgB0 = await sessionB.send('Yep, I get it. Thanks, Alice!');
  let sealB0 = await bob.sealEnvelope(msgB0.to, msgB0);

  let openB0 = await alice.openEnvelope(sealB0);
  let readB0 = await sessionA.read(openB0.contents);

  let msgA2 = await sessionA.send("You're welcome!");
  let sealA2 = await alice.sealEnvelope(msgA2.to, msgA2);

  let openA2 = await bob.openEnvelope(sealA2);
  let readA2 = await sessionB.read(openA2.contents);

  return {alice, bob, bobCard, sessionA, sessionB, msgA0, sealA0, msgA1, sealA1, openA0, readA0, openA1, readA1, msgB0, sealB0, openB0, readB0, msgA2, sealA2, openA2, readA2};

}
